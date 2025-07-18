#include <argp.h>
#include <bpf/libbpf.h>
#include <unistd.h>

#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
// 新增的头文件，用于设备名称映射
#include <map>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "iosnoop.skel.h"
#include "iosnoop.bpf.h"
static volatile bool exiting = false;
// 用于存储设备号到设备名称的映射
static std::map<dev_t, std::string> dev_to_name_map;
struct env {
    long min_latency_ms;
};

static struct env env = {
    .min_latency_ms = 0,
};



static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level > LIBBPF_WARN) {
        return 0;
    }
    return vfprintf(stderr, format, args);
}

static void sig_handler(int sig) {
    exiting = true;
}
// -- 辅助函数 --

// 扫描 /sys/block 并填充设备号到设备名称的映射
// 注意: 需要 C++17 或更高版本以支持 <filesystem>
void populate_device_map() {
    const std::string block_dir = "/sys/block";
    try {
        for (const auto& entry : std::filesystem::directory_iterator(block_dir)) {
            if (entry.is_directory()) {
                std::string dev_name = entry.path().filename().string();
                std::ifstream dev_file(entry.path() / "dev");
                if (dev_file.is_open()) {
                    std::string line;
                    if (std::getline(dev_file, line)) {
                        std::stringstream ss(line);
                        unsigned int maj, min;
                        char colon;
                        ss >> maj >> colon >> min;
                        if (!ss.fail() && colon == ':') {
                            // 使用与eBPF程序相同的逻辑创建dev_t
                            dev_t dev_id = (maj << 20) | min;
                            dev_to_name_map[dev_id] = dev_name;
                        }
                    }
                }
            }
        }
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "警告: 无法读取 /sys/block 来映射设备名称: " << e.what() << std::endl;
    }
}
// 事件处理回调函数
int handle_event(void *ctx, void *data, size_t size) {
    const custom_io_event_t *e = (custom_io_event_t *)data;

    double queue_ms = (double)e->queue_latency_ns / 1000000.0;
    double device_ms = (double)e->device_latency_ns / 1000000.0;
    std::string dev_name;
    auto it = dev_to_name_map.find(e->dev);
    if (it != dev_to_name_map.end()) {
        dev_name = it->second;
    } else {
        // 如果找不到设备名称，则回退显示 主设备号:次设备号
        unsigned int maj = e->dev >> 20;
        unsigned int min = e->dev & ((1U << 20) - 1);
        dev_name = std::to_string(maj) + ":" + std::to_string(min);
    }
    printf("%-10.3f %-16s %-7d %-4s %-10s %-12llu Q:%.3fms D:%.3fms\n",
           (double)e->ts_us / 1000000.0,
           e->comm,
           e->pid,
           e->rw_flag ? "W" : "R",
           dev_name.c_str(), // 打印设备名称字符串
           e->bytes,
           queue_ms,
           device_ms);
    return 0;
    return 0;
}

int main(int argc, char **argv) {
    struct iosnoop_bpf *skel;
    struct ring_buffer *rb = nullptr;
    int err = 0;
    // 在程序开始时填充设备映射
    populate_device_map();

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = iosnoop_bpf__open();
    if (!skel) {
        std::cerr << "错误: 无法打开 BPF 骨架" << std::endl;
        return 1;
    }

    pid_t self_pid = getpid();
    skel->rodata->self_pid = self_pid;
    skel->rodata->min_latency_ms = env.min_latency_ms;

    err = iosnoop_bpf__load(skel);
    if (err) {
        std::cerr << "错误: 无法加载 BPF 骨架: " << err << std::endl;
        iosnoop_bpf__destroy(skel);
        return 1;
    }

    err = iosnoop_bpf__attach(skel);
    if (err) {
        std::cerr << "错误: 无法附加 BPF 骨架: " << err << std::endl;
        iosnoop_bpf__destroy(skel);
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, nullptr, nullptr);
    if (!rb) {
        err = -errno;
        std::cerr << "错误: 无法创建 ring buffer: " << err << std::endl;
        iosnoop_bpf__destroy(skel);
        return 1;
    }


    // 更新表头以适应字符串设备名称
    printf("%-10s %-16s %-7s %-4s %-10s %-12s %s\n",
           "TIME(s)", "COMM", "PID", "T", "DEVICE", "BYTES", "DETAILS");

    std::cout << "正在追踪块设备 I/O (已忽略自身PID: " << self_pid << ")... 按 Ctrl-C 退出。" << std::endl;
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            std::cerr << "轮询 ring buffer 时出错: " << err << std::endl;
            break;
        }
    }

    ring_buffer__free(rb);
    iosnoop_bpf__destroy(skel);

    std::cout << "程序已退出。" << std::endl;
    return 0;
}
