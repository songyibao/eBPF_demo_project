
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "iosnoop.bpf.h"


#define MINORBITS 20

// -- 用户可配置变量 --
volatile const __u32 self_pid = 0;
volatile const __u64 min_latency_ms = 0;

// -- BPF Maps --

// 用于在事件之间传递上下文信息
struct custom_context {
    __u64 insert_t; // 请求插入队列的时间
    __u64 issue_t;  // 请求分派给驱动的时间
    __u32 pid;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct request *);
    __type(value, struct custom_context);
    __uint(max_entries, 10240);
} contexts SEC(".maps");

// 用于向用户空间发送事件的 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");


// -- 块设备层跟踪点 --

SEC("tp_btf/block_rq_insert")
int BPF_PROG(block_rq_insert, struct request *rq)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == self_pid) {
        return 0;
    }

    struct custom_context custom_ctx = {};
    custom_ctx.insert_t = bpf_ktime_get_ns();
    custom_ctx.issue_t = 0;
    custom_ctx.pid = pid;
    bpf_get_current_comm(custom_ctx.comm, sizeof(custom_ctx.comm));

    bpf_map_update_elem(&contexts, &rq, &custom_ctx, BPF_ANY);
    return 0;
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(block_rq_issue, struct request *rq)
{
    struct custom_context *ctx_ptr = bpf_map_lookup_elem(&contexts, &rq);
    if (ctx_ptr) {
        ctx_ptr->issue_t = bpf_ktime_get_ns();
    }
    return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *rq, int error, unsigned int nr_bytes)
{
    struct custom_context *ctx_ptr = bpf_map_lookup_elem(&contexts, &rq);
    if (!ctx_ptr) {
        return 0;
    }

    __u64 complete_t = bpf_ktime_get_ns();
    __u64 total_latency_ns = complete_t - ctx_ptr->insert_t;

    // 清理上下文映射中的条目
    bpf_map_delete_elem(&contexts, &rq);

    if (min_latency_ms > 0 && total_latency_ns < (min_latency_ms * 1000000)) {
        return 0;
    }

    struct custom_io_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // 从上下文中恢复 PID 和进程名
    e->pid = ctx_ptr->pid;
    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), ctx_ptr->comm);

    e->ts_us = complete_t / 1000;
    e->bytes = nr_bytes;

    // 使用 BPF_CORE_READ 安全地访问内核结构体字段
    struct gendisk *disk = BPF_CORE_READ(rq, q, disk);
    if (disk) {
        __u32 major = BPF_CORE_READ(disk, major);
        __u32 first_minor = BPF_CORE_READ(disk, first_minor);
        e->dev = ((major << MINORBITS) | first_minor);
    } else {
        e->dev = 0;
    }

    if (ctx_ptr->issue_t > 0) {
        e->queue_latency_ns = ctx_ptr->issue_t - ctx_ptr->insert_t;
        e->device_latency_ns = complete_t - ctx_ptr->issue_t;
    } else {
        // 如果错过了 issue 事件
        e->queue_latency_ns = 0;
        e->device_latency_ns = total_latency_ns;
    }

    // 使用 BPF_CORE_READ 安全地访问 op 字段
    e->rw_flag = (BPF_CORE_READ(rq, cmd_flags) == REQ_OP_WRITE);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";