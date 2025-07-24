// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "vfsnoop.bpf.h"

// <<< 新增: 定义一些常见虚拟文件系统的魔数 (Magic Number)
#define PROC_SUPER_MAGIC    0x9fa0
#define SYSFS_MAGIC         0x62656572
#define TMPFS_MAGIC         0x01021994
#define BPF_FS_MAGIC        0xcafe4a11
#define CGROUP2_SUPER_MAGIC 0x63677270 // <<< 新增 Cgroup v2 的魔数

// -- 用户可配置变量 --
volatile const __u32 self_pid = 0;
volatile const __u64 min_latency_ms = 0;
volatile const __u32 target_pid = 0;

// -- BPF Maps --

// 【已修改】用于在 vfs 操作的入口和出口之间传递上下文
struct vfs_context {
    u64 start_ts;
    u64 count;
    struct file *file;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct vfs_context);
    __uint(max_entries, 10240);
} active_vfs_ops SEC(".maps");

// 用于向用户空间发送事件的 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// <<< 新增: 辅助函数，用于检查文件类型是否为磁盘文件
static __always_inline bool is_disk_file(struct file *file) {
    if (!file) {
        return false;
    }

    // 从 file->f_path.dentry->d_inode 获取 i_mode
    // 使用 BPF_CORE_READ 保证可移植性
    // 1. 从 file 结构体逐层深入，获取到 super_block
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    struct super_block *sb = BPF_CORE_READ(inode, i_sb);

    // 2. 读取 super_block 中的魔数 s_magic
    unsigned long magic = BPF_CORE_READ(sb, s_magic);

    // 3. 判断魔数是否属于我们想要排除的虚拟文件系统
    switch (magic) {
        case PROC_SUPER_MAGIC:
        case SYSFS_MAGIC:
        case TMPFS_MAGIC:
        case BPF_FS_MAGIC:
        case CGROUP2_SUPER_MAGIC:
            return false; // 如果是这些虚拟文件系统，则判定为非磁盘文件
        default:
            break;
    }

    // S_ISREG 判断是否是常规文件
    // S_ISBLK 判断是否是块设备
    umode_t mode = BPF_CORE_READ(inode, i_mode);
    if ((((mode) & 00170000) == 0100000) || (((mode) & 00170000) == 0060000)) {
        return true;
    }

    return false;
}

// -- VFS Probes --

// 统一的 VFS 操作入口探针
static int enter_vfs_op(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (pid == self_pid || (target_pid != 0 && pid != target_pid)) {
        return 0;
    }

    // 【新增】捕获函数参数以获取更详细的上下文
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    u64 count = (u64)PT_REGS_PARM3(ctx);

    // <<< 修改: 在记录之前，先检查文件类型
    if (!is_disk_file(file)) {
        return 0; // 不是磁盘文件，直接忽略
    }

    // 存储包含时间戳、请求字节数和文件指针的完整上下文
    struct vfs_context context = {};
    context.start_ts = bpf_ktime_get_ns();
    context.count = count;
    context.file = file;

    bpf_map_update_elem(&active_vfs_ops, &id, &context, BPF_ANY);
    return 0;
}

// 统一的 VFS 操作出口探针
static int exit_vfs_op(struct pt_regs *ctx, int op_type) {
    u64 id = bpf_get_current_pid_tgid();
    // 查找对应的上下文
    struct vfs_context *context_ptr = bpf_map_lookup_elem(&active_vfs_ops, &id);
    if (!context_ptr) {
        return 0;
    }

    u64 latency_ns = bpf_ktime_get_ns() - context_ptr->start_ts;

    // 必须在函数返回前删除映射条目
    bpf_map_delete_elem(&active_vfs_ops, &id);

    if (min_latency_ms > 0 && latency_ns < min_latency_ms * 1000000) {
        return 0;
    }

    struct vfs_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->ts_us = bpf_ktime_get_ns() / 1000;
    e->pid = id >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    e->latency_ns = latency_ns;
    e->ret = PT_REGS_RC(ctx);
    e->vfs_op = op_type;
    // 【新增】从上下文中恢复请求的字节数
    e->count = context_ptr->count;

    // 【新增】从文件指针安全地读取文件名
    // 使用 BPF_CORE_READ 宏来增强可移植性
    // .dentry
    struct file *file = context_ptr->file;
    struct path fpath = BPF_CORE_READ(file, f_path);
    struct dentry *dentry = fpath.dentry;
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), BPF_CORE_READ(dentry, d_name.name));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// -- 挂载点 --

// SEC("kprobe/vfs_read")
// int BPF_KPROBE(vfs_read_enter) { return enter_vfs_op(ctx); }
//
// SEC("kretprobe/vfs_read")
// int BPF_KRETPROBE(vfs_read_exit) { return exit_vfs_op(ctx, 0); } // 0 for read

SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write_enter) { return enter_vfs_op(ctx); }

SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(vfs_write_exit) { return exit_vfs_op(ctx, 1); } // 1 for write

char LICENSE[] SEC("license") = "GPL";
