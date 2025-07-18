#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "exitsnoop.bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
    struct task_struct *task, *parent_task;
    const struct cred *cred; // 定义一个指向 cred 结构体的指针
    exitsnoop_event_t *e;
    __u32 pid, tid;
    u64 id, ts, *start_ts, start_time = 0;

    /* get PID and TID of exiting thread/process */
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    /* ignore thread exits */
    if (pid != tid)
        return 0;

    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* fill out the sample with data */
    task = (struct task_struct *)bpf_get_current_task();
    start_time = BPF_CORE_READ(task, start_time);

    e->duration_ns = bpf_ktime_get_ns() - start_time;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // 获取父进程名称
    parent_task = BPF_CORE_READ(task, real_parent);
    // 2. 从父进程的 task_struct 中读取 comm (进程名)
    char *pcomm = BPF_CORE_READ(parent_task, comm);
    bpf_core_read_str(e->pcomm,sizeof(e->pcomm),pcomm);


    /* --- 新增：获取进程的用户信息 (UID) --- */
    // 1. 从 task_struct 中读取指向 cred 结构体的指针
    cred = BPF_CORE_READ(task, cred);
    // 2. 从 cred 结构体中读取 uid (类型为 kuid_t)，并提取其 val 成员
    e->uid = BPF_CORE_READ(cred, uid.val);
    /* --- 新增结束 --- */

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}