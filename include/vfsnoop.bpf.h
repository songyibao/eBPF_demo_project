#ifndef __ANALYZER_H
#define __ANALYZER_H

// 定义任务名（进程名）的最大长度
#define TASK_COMM_LEN 32
// 定义文件名的最大长度
#define FILENAME_LEN 256

// 定义内核传递给用户空间的 VFS 事件结构体
struct vfs_event {
    // 事件完成时的时间戳 (单位：微秒)
    __u64 ts_us;
    // 发起I/O的进程ID
    __u32 pid;
    // vfs_read/write 系统调用的总耗时 (单位：纳秒)
    __u64 latency_ns;
    // 【新增】应用程序请求读/写的字节数
    __u64 count;
    // 系统调用的返回值 (例如，成功读写的字节数)
    __s64 ret;
    // VFS 操作类型 (0 代表 read, 1 代表 write)
    int vfs_op;
    // 发起I/O的进程名
    char comm[TASK_COMM_LEN];
    // 【新增】操作的文件名
    char filename[FILENAME_LEN];
};

#endif /* __ANALYZER_H */
