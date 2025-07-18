//
// Created by syb on 25-7-5.
//
#include <iostream>
#include <string>
#include <sstream> // 用于高效构建字符串
#include <chrono>
#include <csignal>
#include <arpa/inet.h>
#include <netinet/in.h> // for inet_ntop
#include <sys/socket.h> // for AF_INET6

// libbpf C 库头文件
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// 通过 bpftool 生成的 eBPF 程序骨架
#include "dns.skel.h"
#include "dns.bpf.h" // 确保包含了定义 dns_event_t 的头文件
#include "utils.h"

// 控制主循环的原子布尔值
static volatile bool running = true;
// --- 信号处理函数 ---
void sig_handler(int signum) {
    running = false;
    std::cerr << "\n收到信号 " << signum << ", 正在退出程序..." << std::endl;
}

// 将 DNS 类型代码转换为字符串
std::string dns_type_to_string(uint16_t qtype) {
    switch (qtype) {
        case 1: return "A";
        case 28: return "AAAA";
        case 5: return "CNAME";
        default: return "TYPE" + std::to_string(qtype);
    }
}

// 将 DNS 响应码转换为字符串
std::string rcode_to_string(uint8_t rcode) {
    switch (rcode) {
        case 0: return "NoError";
        case 1: return "FormErr";
        case 2: return "ServFail";
        case 3: return "NXDomain";
        case 4: return "NotImp";
        case 5: return "Refused";
        default: return "RCODE" + std::to_string(rcode);
    }
}
// CNAME类型的请求，需要额外手动解析一次域名指针
std::string parse_cname_from_cname_raw_data(const dns_event_t *e, const dns_answer_t* ans) {
    // 根据DNS协议的资源记录中的资源
    // 数据长度 ans->len
    // cname raw_data: ans->data.cname 它可能是0或多个(1byte len + len bytes 的字符串)最后跟上一个2 byte的域名指针
    // 其中前2bit是11 后面14bit是指向域名的偏移量，这个偏移量是相对于整个DNS报文的起始位置的，而DNS报文的头字段为12字节
    // 因此需要将偏移量减去12字节的头部字段长度，得到相对于DNS问题记录的开始位置的偏移量，又因为qname的raw_data格式为1byte len + len bytes 的字符串
    // 所以需要将偏移量再减去1，得到相对于qname开始字符的偏移量，也就是域名指针所代表的字符串的开头在qname中的索引
    // 有了索引，就可以直接从qname中提取出域名指针指向的字符串
    // 这里的假设是 问题记录 不会使用域名指针，且，域名指针后面不会再有name内容
    // 先解析域名指针前面的内容
    std::string cname_str;
    __u8 index = 0;
    __u8 label_len = 0;
    while (index < ans->len) {
        label_len = ans->data.cname[index];
        if (label_len == 0) {
            // 遇到0长度的标签，表示域名结束
            break;
        }
        if (label_len & 0xc0) {
            // 如果标签长度的高2位是11，表示这是一个域名指针
            // 计算偏移量，减去12字节的头部长度和1字节的标签长度
            index = ((label_len & 0x3f) << 8) | ans->data.cname[index + 1];
            index -= 12; // 减去DNS头部长度
            index -= 1; // 减去标签长度字节
            // 从问题记录中提取域名指针指向的字符串
            cname_str.append(e->qname + index);
            break;
        }
        index++; // 跳过标签长度字节
        // 检查标签长度是否超过最大长度
        if (label_len > MAX_DOMAIN_NAME_LEN - cname_str.size() - 1) {
            // 如果标签长度超过最大长度，截断
            label_len = MAX_DOMAIN_NAME_LEN - cname_str.size() - 1;
        }
        // 将标签内容添加到 cname_str 中
        cname_str.append(ans->data.cname + index, label_len);
        index += label_len; // 移动到下一个标签
        // 添加点号分隔符
        if (index < ans->len) {
            cname_str += '.';
        }
    }
    // 如果 cname_str 以点号结尾，去掉最后的点号
    if (!cname_str.empty() && cname_str.back() == '.') {
        cname_str.pop_back();
    }
    // 如果 cname_str 为空，返回 cname_parse_error
    if (cname_str.empty()) {
        return "cname_parse_error";
    }
    return cname_str;
}

// --- Ring Buffer 回调函数 (核心修改) ---
// 当 eBPF 程序向 Ring Buffer 发送数据时，libbpf 会调用此函数
int handle_event(void *ctx, void *data, size_t size) {
    auto *e = static_cast<dns_event_t *>(data);

    // 使用 stringstream 高效构建 JSON 字符串
    std::stringstream json_log;
    json_log << "{";
    json_log << R"("timestamp":)" << getTimestampMs() << ",";
    json_log << R"("latency_ms":)" << static_cast<double>(e->latency_ns) / 1.0e6 << ",";
    json_log << R"("client":")" << ipv4_to_string(e->saddr) << R"(",)";
    // json_log << R"("process:")" << std::string(e->comm) << R"(",)";
    json_log << R"("nameserver":")" << ipv4_to_string(e->daddr) << R"(",)";
    json_log << R"("domain_name":")" << bytes_to_string(e->qname, MAX_DOMAIN_NAME_LEN) << R"(",)";
    json_log << R"("query_type":")" << dns_type_to_string(e->qtype) << R"(",)";
    json_log << R"("response_code":")" << rcode_to_string(e->rcode) << R"(",)";
    json_log << R"("dns_identifier":)" << e->tx_id << ",";
    json_log << R"("answer_count":)" << e->answer_count << ",";

    // 构建嵌套的 answers 数组
    json_log << R"("answers":[)";
    for (int i = 0; i < e->answer_count; ++i) {
        const dns_answer_t* ans = &e->answers[i];
        json_log << "{";
        json_log << R"("type":")" << dns_type_to_string(ans->rtype) << R"(",)";
        json_log << R"("ttl":)" << ans->ttl << ",";
        json_log << R"("data":")";

        switch (ans->rtype) {
            case DNS_TYPE_A:
                json_log << ipv4_to_string(ans->data.ipv4);
                break;
            case DNS_TYPE_AAAA:
                json_log << ipv6_to_string(ans->data.ipv6);
                break;
            case DNS_TYPE_CNAME:
                // 对 JSON 字符串中的特殊字符进行转义，例如引号
                json_log << parse_cname_from_cname_raw_data(e, ans);
                break;
            default:
                json_log << "unsupported_data_type";
                break;
        }
        json_log << R"("})";
        // 如果不是最后一个元素，则添加逗号
        if (i < e->answer_count - 1) {
            json_log << ",";
        }
    }
    json_log << "]"; // 结束 answers 数组
    json_log << "}"; // 结束整个 JSON 对象

    // 将完整的 JSON 字符串打印到标准输出
    std::cout << json_log.str() << std::endl;

    return 0;
}


int main(int argc, char **argv) {
    struct dns_bpf* skel;
    struct ring_buffer* rb = nullptr;
    int err;

    // --- 1. 设置 libbpf 和 eBPF 程序 ---
    skel = dns_bpf__open_and_load();
    if (!skel) {
        std::cerr << "Failed to open and load BPF skeleton" << std::endl;
        return 1;
    }

    err = dns_bpf__attach(skel);
    if (err) {
        std::cerr << "Failed to attach BPF skeleton: " << err << std::endl;
        goto cleanup;
    }
    // 将提示信息输出到 stderr，以避免污染 stdout 的 JSON 日志流
    std::cerr << "BPF program successfully loaded and attached." << std::endl;

    // --- 2. 设置 Ring Buffer ---
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, nullptr, nullptr);
    if (!rb) {
        err = -1;
        std::cerr << "Failed to create ring buffer" << std::endl;
        goto cleanup;
    }

    // --- 3. 设置信号处理并进入主循环 ---
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    std::cerr << "Listening for DNS events... Press Ctrl+C to exit." << std::endl;

    while (running) {
        err = ring_buffer__poll(rb, 100); // 轮询 Ring Buffer
        if (err == -EINTR) {
            err = 0;
            continue;
        }
        if (err < 0) {
            std::cerr << "Error polling ring buffer: " << err << std::endl;
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    dns_bpf__destroy(skel);
    std::cerr << "BPF resources cleaned up." << std::endl;

    return err < 0 ? -err : 0;
}
