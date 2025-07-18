#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "dns.bpf.h"
/**
 * DNS payload
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1); // 只需一个条目
    __type(key, u32); // 键是 32 位整数
    __type(value, unsigned char[MAX_DNS_PAYLOAD_SIZE]); // 值是 512 字节的数组
} dns_buffer_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1); // 只需一个条目
    __type(key, u32); // 键是 32 位整数
    __type(value, unsigned char[MAX_DOMAIN_NAME_LEN]); // 值是 512 字节的数组
} qname_buffer_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct dns_key);
    __type(value, u64);
} start_times SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

bool is_common_dns_record_type(uint16_t type) {
    switch (type) {
        case DNS_TYPE_A:
        case DNS_TYPE_AAAA:
        case DNS_TYPE_CNAME:
            return true;
        default:
            return false;
    }
}

static __always_inline unsigned char get_kernel_byte(const unsigned char* ptr) {
    unsigned char value;
    bpf_core_read(&value, 1, ptr);
    return value;
}

static __always_inline
int parse_dns(const unsigned char* dns_payload, dns_event_t* dns_event) {
    if (!dns_event || !dns_payload) {
        return -1;
    }
    // 1. 首先判断响应吗是否为0，出错则不继续解析
    const unsigned char* pos = dns_payload;
    dns_header_t dns_header = {};
    if (pos + 12 >= dns_payload + MAX_DNS_PAYLOAD_SIZE) {
        return -1;
    }
    bpf_core_read(&dns_header, 12, dns_payload);
    pos += 12;
    dns_header.id = bpf_ntohs(dns_header.id);
    dns_header.flags = bpf_ntohs(dns_header.flags);
    dns_header.qdcount = bpf_ntohs(dns_header.qdcount);
    dns_header.ancount = bpf_ntohs(dns_header.ancount);
    dns_header.nscount = bpf_ntohs(dns_header.nscount);
    dns_header.arcount = bpf_ntohs(dns_header.arcount);

    // 判断标识中的响应码：2个字节 16位中的右边4位
    dns_event->rcode = dns_header.flags & 0x000F;
    if (dns_event->rcode != 0) {
        dns_event->answer_count = 0;
        return -1;
    }
    // 2. 响应正常，继续解析 Queries
    if (dns_header.qdcount != 1) {
        bpf_printk("%s", "仅支持查询记录数量为1的DNS报文");
        return -1;
    }
    // 3. Queries 数量正常，开始解析
    if (pos + 2 >= dns_payload + MAX_DNS_PAYLOAD_SIZE) {
        return -1;
    }
    __u8 label_length = get_kernel_byte(pos);
    if ((label_length & 0xC0) == 0xC0) {
        bpf_printk("%s", "只有一条query，不应该有域名指针");
        return -1;
    }
    pos += 1;
    __u8 qname_index = 0;
    for (int i = 0; i < MAX_DNS_NAME_LABELS; i++) {
        if (label_length == 0) {
            // 达到域名结尾
            break;
        }
        if (pos + label_length >= dns_payload + MAX_DNS_PAYLOAD_SIZE) {
            return -1;
        }
        if (qname_index + label_length >= MAX_DOMAIN_NAME_LEN) {
            return -1;
        }
        bpf_core_read(dns_event->qname+qname_index, label_length, pos);
        pos += label_length;
        qname_index += label_length;
        if (qname_index >= MAX_DOMAIN_NAME_LEN) {
            return -1;
        }
        dns_event->qname[qname_index++] = '.';
        if (pos + 1 >= dns_payload + MAX_DNS_PAYLOAD_SIZE) {
            return -1;
        }
        bpf_core_read(&label_length, 1, pos);
        pos += 1;
    }
    __u8 end_index = qname_index - 1;
    if (end_index < 0 || end_index >= MAX_DOMAIN_NAME_LEN) {
        return -1;
    }
    dns_event->qname[end_index] = '\0';
    qname_index = end_index;
    // dns_event->qname_length = qname_index;
    // query 的 type
    if (pos + 2 >= dns_payload + MAX_DNS_PAYLOAD_SIZE) {
        return -1;
    }
    bpf_core_read(&dns_event->qtype, 2, pos);
    pos += 2;
    dns_event->qtype = bpf_ntohs(dns_event->qtype);
    if (!is_common_dns_record_type(dns_event->qtype)) {
        bpf_printk("%s", "不支持的DNS Query 类型");
        return -1;
    }
    // 跳过 class
    pos += 2;
    // pos 来到 Answers，假设 answer使用的都是域名指针
    dns_event->answer_count = dns_header.ancount;
    for (int i = 0; i < MAX_ANSWERS - 1; i++) {
        if (i >= dns_event->answer_count) {
            break;
        }
        // 域名指针，和长度共用两字节,直接跳过，我们只关心解析结果
        pos += 2;
        bpf_core_read(&dns_event->answers[i].rtype, 2, pos);
        pos += 2;
        dns_event->answers[i].rtype = bpf_ntohs(dns_event->answers[i].rtype);
        if (!is_common_dns_record_type(dns_event->answers[i].rtype)) {
            // bpf_printk("%s", "不支持的DNS Answer rtype 类型");
            return -1;
        }
        // 跳过class
        pos += 2;
        bpf_core_read(&dns_event->answers[i].ttl, 4, pos);
        pos += 4;
        dns_event->answers[i].ttl = bpf_ntohl(dns_event->answers[i].ttl);
        __u16 RDLength = 0;

        bpf_core_read(&RDLength, 2, pos);
        pos += 2;
        RDLength = bpf_ntohs(RDLength);
        dns_event->answers[i].len = RDLength;
        if (dns_event->answers[i].rtype == DNS_TYPE_CNAME) {
            // 简化CNAME处理：只处理完整域名，跳过域名指针解析
            if (RDLength >= MAX_DOMAIN_NAME_LEN) {
                return -1;
            }

            // 直接将CNAME数据复制，不进行复杂的域名指针解析,放在用户代理中解析
            bpf_core_read(dns_event->answers[i].data.cname, RDLength, pos);

            // 简单的NULL终止处理
            if (RDLength < MAX_DOMAIN_NAME_LEN) {
                dns_event->answers[i].data.cname[RDLength] = '\0';
            } else {
                dns_event->answers[i].data.cname[MAX_DOMAIN_NAME_LEN - 1] =
                    '\0';
            }

            pos += RDLength;
        } else {
            // 其他记录直接拷贝过来
            // ipv6长度16字节 128位,简单校验
            if (RDLength > 16) {
                // 超出了 data buffer 长度
                bpf_printk("%s", "数据长度过长，超出正常范围");
                return -1;
            }
            if (pos + RDLength >= dns_payload + MAX_DNS_PAYLOAD_SIZE) {
                bpf_printk("%s", "数据长度过长，超出边界");
                return -1;
            }
            bpf_core_read(&dns_event->answers[i].data, RDLength, pos);

            pos += RDLength;
            if (RDLength >= MAX_DOMAIN_NAME_LEN) {
                bpf_printk("%s", "数据长度过长，超出域名长度范围");
                return -1;
            }
        }
    }
    return 0;
}


SEC("kprobe/ip_send_skb")
int BPF_KPROBE(kprobe_ip_send_skb, struct net *net, struct sk_buff *skb) {
    if (!skb)
        return 0;

    void* head = BPF_CORE_READ(skb, head);
    __u16 network_header = BPF_CORE_READ(skb, network_header);
    struct iphdr* iph = (struct iphdr*)(head + network_header);

    __u8 ver_ihl_byte;
    bpf_core_read(&ver_ihl_byte, sizeof(ver_ihl_byte), iph);
    __u8 version = ver_ihl_byte >> 4;
    __u8 ihl = ver_ihl_byte & 0x0F;

    if (version != 4)
        return 0;
    if (BPF_CORE_READ(iph, protocol) != IPPROTO_UDP)
        return 0;
    if (ihl < 5)
        return 0;


    struct udphdr* udph = (struct udphdr*)((void*)iph + ihl * 4);

    __u16 dport = BPF_CORE_READ(udph, dest);
    if (dport != bpf_htons(53))
        return 0;
    struct dns_key key = {};
    bpf_core_read(&key.saddr, sizeof(key.saddr), &iph->saddr);
    bpf_core_read(&key.daddr, sizeof(key.daddr), &iph->daddr);
    key.sport = BPF_CORE_READ(udph, source);
    key.dport = dport;

    void* dns_data = (void*)udph + sizeof(struct udphdr);
    bpf_core_read(&key.id, sizeof(key.id), dns_data);

    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
    return 0;
}

SEC("kprobe/udp_queue_rcv_skb")
int BPF_KPROBE(kprobe_udp_queue_rcv_skb, struct sock *sk, struct sk_buff *skb) {
    if (!sk || !skb)
        return 0;
    if (BPF_CORE_READ(skb, data_len) != 0) {
        // 存在非线性数据，不处理
        return 0;
    }

    void* head = BPF_CORE_READ(skb, head);
    __u16 network_header = BPF_CORE_READ(skb, network_header);
    struct iphdr* iph = (struct iphdr*)(head + network_header);

    __u8 ver_ihl_byte;
    bpf_core_read(&ver_ihl_byte, sizeof(ver_ihl_byte), iph);
    __u8 version = ver_ihl_byte >> 4;
    __u8 ihl = ver_ihl_byte & 0x0F;

    if (version != 4)
        return 0;

    if (BPF_CORE_READ(iph, protocol) != IPPROTO_UDP)
        return 0;
    if (ihl < 5)
        return 0;

    struct udphdr* udph = (struct udphdr*)((void*)iph + ihl * 4);
    __u16 sport = BPF_CORE_READ(udph, source);
    if (sport != bpf_htons(53))
        return 0;
    struct dns_key dns_key = {};
    // 为了匹配请求时的key，我们需要交换响应包的源和目的信息
    // 请求的源IP = 响应的目的IP
    bpf_core_read(&dns_key.saddr, sizeof(dns_key.saddr), &iph->daddr);
    // 请求的目的IP = 响应的源IP
    bpf_core_read(&dns_key.daddr, sizeof(dns_key.daddr), &iph->saddr);
    // 请求的源端口 = 响应的目的端口
    dns_key.sport = BPF_CORE_READ(udph, dest);
    // 请求的目的端口 = 响应的源端口 (53)
    dns_key.dport = sport;

    /* data length = total length - ip header length - udp header length */
    size_t dns_payload_len =
        bpf_ntohs(BPF_CORE_READ(udph,len)) - sizeof(struct udphdr);
    // size_t dns_payload_len = 300; // 直接使用300字节作为测试数据长度
    if (dns_payload_len > 512)
        return 0;
    // bpf_printk("dns_payload_len: %lu", dns_payload_len);
    // bpf_printk("%s","从映射中获取缓冲区");
    // 从映射中获取缓冲区
    u32 key = 0;
    unsigned char* dns_buffer = bpf_map_lookup_elem(&dns_buffer_map, &key);

    if (!dns_buffer)
        return 0;
    // 将数据加载到映射的缓冲区中
    void* dns_data = (void*)udph + sizeof(struct udphdr);
    bpf_core_read(&dns_key.id, sizeof(dns_key.id), dns_data);
    // unsigned char *dns_data = BPF_CORE_READ(skb,data);
    long ret = bpf_core_read(dns_buffer, dns_payload_len, dns_data);
    if (ret < 0)
        return 0;



    // 到以上没有问题
    dns_event_t* e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __u64 id = bpf_get_current_pid_tgid();
    // e->pid = id;    // 线程 ID
    // e->tgid = id >> 32;     // 进程 ID
    // bpf_get_current_comm(e->comm, sizeof(e->comm));

    int res = parse_dns(dns_buffer, e);
    if (res != 0) {
        bpf_printk("%s", "parse failed");
        goto exit;
    }

    u64* start_ts = bpf_map_lookup_elem(&start_times, &dns_key);
    if (!start_ts) {
        bpf_printk("%s", "dns key not found");
        goto exit;
    };
    u64 latency = bpf_ktime_get_ns() - *start_ts;
    bpf_map_delete_elem(&start_times, &dns_key);
    e->latency_ns = latency;
    e->saddr = dns_key.saddr;
    e->sport = dns_key.sport;
    e->daddr = dns_key.daddr;
    e->dport = dns_key.dport;
    e->tx_id = dns_key.id;
    bpf_ringbuf_submit(e, 0);
    return 0;
exit:
    bpf_ringbuf_discard(e, 0);
    return 0;
}