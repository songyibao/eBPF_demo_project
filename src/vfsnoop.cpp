#include <iostream>
#include <string>
#include <vector>
#include <csignal>
#include <argp.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "vfsnoop.bpf.h"
#include "vfsnoop.skel.h"
#include "utils.h"

// -- 全局变量 --
static volatile bool exiting = false;

// -- 命令行参数解析 --
static const char doc[] = "一个使用eBPF分析VFS层I/O延迟的工具 (详细版)。\n\n"
                          "它可以追踪 read/write 调用的总耗时、请求字节数、返回值和文件名。\n"
                          "USAGE: ./vfs-latency-analyzer [-m <min-latency-ms>] [-p <pid>]";

static const struct argp_option opts[] = {
    { "min-latency", 'm', "LATENCY", 0, "仅显示延迟超过此毫秒数的I/O事件", 0 },
    { "pid", 'p', "PID", 0, "仅追踪此PID的I/O请求", 0 },
    { NULL, 0, 0, 0, NULL, 0 }
};

struct env {
    long min_latency_ms;
    pid_t target_pid;
};

static struct env env = {
    .min_latency_ms = 0,
    .target_pid = 0,
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch (key) {
        case 'm':
            errno = 0;
            env.min_latency_ms = strtol(arg, NULL, 10);
            if (errno || env.min_latency_ms < 0) {
                std::cerr << "无效的延迟值: " << arg << std::endl;
                argp_usage(state);
            }
            break;
        case 'p':
            errno = 0;
            env.target_pid = strtol(arg, NULL, 10);
            if (errno || env.target_pid <= 0) {
                std::cerr << "无效的 PID: " << arg << std::endl;
                argp_usage(state);
            }
            break;
        case ARGP_KEY_ARG:
            argp_usage(state);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = doc,
};

// -- 辅助函数 --

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level > LIBBPF_WARN) {
        return 0;
    }
    return vfprintf(stderr, format, args);
}

static void sig_handler(int sig) {
    exiting = true;
}

// 事件处理回调函数
int handle_event(void *ctx, void *data, size_t size) {
    const struct vfs_event *e = (struct vfs_event *)data;

    double latency_ms = (double)e->latency_ns / 1000000.0;

    // 【已修改】打印新增的详细信息
    printf("timestamp=%-lu processName=\"%s\" pid=%d type=%s latency=%f req_size=%llu ret_size=%lld file=%s\n",
           // (double)e->ts_us / 1000000.0,
           getTimestampMs(),
           e->comm,
           e->pid,
           e->vfs_op == 1 ? "WRITE" : "READ",
           latency_ms,
           e->count, // 请求字节数
           e->ret,   // 返回值
           e->filename); // 文件名
    return 0;
}

int main(int argc, char **argv) {
    struct vfsnoop_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) {
        return err;
    }

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = vfsnoop_bpf__open();
    if (!skel) {
        std::cerr << "错误: 无法打开 BPF 骨架" << std::endl;
        return 1;
    }

    pid_t self_pid = getpid();
    skel->rodata->self_pid = self_pid;
    skel->rodata->min_latency_ms = env.min_latency_ms;
    skel->rodata->target_pid = env.target_pid;

    err = vfsnoop_bpf__load(skel);
    if (err) {
        std::cerr << "错误: 无法加载 BPF 骨架: " << err << std::endl;
        vfsnoop_bpf__destroy(skel);
        return 1;
    }

    err = vfsnoop_bpf__attach(skel);
    if (err) {
        std::cerr << "错误: 无法附加 BPF 骨架: " << err << std::endl;
        vfsnoop_bpf__destroy(skel);
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -errno;
        std::cerr << "错误: 无法创建 ring buffer: " << err << std::endl;
        vfsnoop_bpf__destroy(skel);
        return 1;
    }

    // 【已修改】更新表头以反映新增的列
    // printf("%-10s %-32s %-7s %-5s %-10s %-21s %s\n",
    //        "TIME(s)", "COMM", "PID", "OP", "LAT(ms)", "BYTES (REQ/RET)", "FILENAME");

    if (env.target_pid != 0) {
        std::cout << "正在追踪 VFS I/O (目标PID: " << env.target_pid << ", 已忽略自身PID: " << self_pid << ")... 按 Ctrl-C 退出。" << std::endl;
    } else {
        std::cout << "正在追踪 VFS I/O (所有进程, 已忽略自身PID: " << self_pid << ")... 按 Ctrl-C 退出。" << std::endl;
    }

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            std::cerr << "轮询 ring buffer 时出错: " << err << std::endl;
            break;
        }
    }

    ring_buffer__free(rb);
    vfsnoop_bpf__destroy(skel);

    std::cout << "程序已退出。" << std::endl;
    return 0;
}
