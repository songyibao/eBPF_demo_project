//
// Created by syb on 25-7-7.
//

#ifndef EXITSNOOP_BPF_H
#define EXITSNOOP_BPF_H

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif //TASK_COMM_LEN

#define MAX_FILENAME_LEN 127

typedef struct exitsnoop_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    unsigned int exit_code;
    unsigned long long duration_ns;
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
} exitsnoop_event_t;
#endif //EXITSNOOP_BPF_H
