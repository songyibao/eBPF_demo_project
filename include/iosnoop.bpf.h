//
// Created by syb on 25-7-9.
//

#ifndef IOSNOOP_BPF_H
#define IOSNOOP_BPF_H

// 定义任务名（进程名）的最大长度
#define TASK_COMM_LEN 16

// 定义内核传递给用户空间的事件结构体
// 只包含块设备层的延迟信息
typedef struct custom_io_event {
    // 事件完成时的时间戳 (单位：微秒)
    __u64 ts_us;
    // 发起I/O的进程ID
    __u32 pid;
    // 设备号 (主设备号 + 次设备号)
    __u32 dev;
    // I/O请求在调度器队列中等待的时间 (单位：纳秒)
    __u64 queue_latency_ns;
    // I/O请求在驱动和硬件上处理的时间 (单位：纳秒)
    __u64 device_latency_ns;
    // I/O请求的大小 (单位：字节)
    __u64 bytes;
    // 读写标志 (1 代表写, 0 代表读)
    int rw_flag;
    // 发起I/O的进程名
    char comm[TASK_COMM_LEN];
} custom_io_event_t;


#endif //IOSNOOP_BPF_H
