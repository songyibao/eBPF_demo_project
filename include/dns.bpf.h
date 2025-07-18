//
// Created by syb on 25-6-30.
//

#ifndef DNS_LATENCY_H
#define DNS_LATENCY_H

// 用于在请求和响应之间匹配的键
struct dns_key {
    __u32 saddr; // 源IP
    __u32 daddr; // 目的IP
    __u16 sport; // 源端口
    __u16 dport; // 目的端口
    __u16 id;    // DNS 事务 ID
};
#define NAME_BUFFER_SIZE 256
#define IP_BUFFER_SIZE 16
#define DNS_TYPE_A      1
#define DNS_TYPE_AAAA   28
#define DNS_TYPE_NS     2
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_MX     15
#define DNS_TYPE_TXT    16

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
// #define TA
#endif


#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif // TASK_COMM_LEN


// BPF对循环次数有限制，定义一个足够大但合理的最大值
#define MAX_DNS_NAME_LABELS 5 // 域名中的最大标签数，例如 'www.google.com' 有3个
#define MAX_DNS_QUESTIONS 1 // 通常DNS请求只有一个问题
#define MAX_DNS_PAYLOAD_SIZE 512

// 定义一些常量，以符合DNS协议规范和eBPF的限制
// DNS域名最大长度为255字节
#define MAX_DOMAIN_NAME_LEN 255
// 我们假设一个DNS回复最多处理16个Answer记录，这是一个权衡值，可以根据实际情况调整
#define MAX_ANSWERS 16
typedef struct {
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} dns_header_t;

/*
 * @struct dns_answer_t
 * @brief 用于描述单个DNS Answer记录
 */
typedef struct dns_answer{
    // 该 answer 记录的类型 (e.g., A: 1, AAAA: 28, CNAME: 5)
    __u16 rtype;
    __u16 len; // 数据长度

    // Time-To-Live
    __u32 ttl;
    union {
        // A记录是IPv4地址，AAAA是IPv6地址，CNAME是另一个域名
        __be32 ipv4;

        // 用于 AAAA 记录 (IPv6)
        // in6_addr 结构体在内核中定义，更标准
        __be32 ipv6[4];
        // 用于 CNAME 记录 (另一个域名)
        char cname[MAX_DOMAIN_NAME_LEN];
    } data;

} dns_answer_t;

/*
 * @struct dns_event_t
 * @brief 用于描述一个完整的DNS查询事件（包括问题和多个答案）
 * 这个结构体将通过 perf buffer 或 ring buffer 从 eBPF 程序发送到用户空间
 */
typedef struct dns_event{
    // __u32 qname_length;   // 查询的域名的长度,不包含结尾的\0
    char qname[MAX_DOMAIN_NAME_LEN]; // 查询的域
    // 存储多个 answer 记录的数组
    struct dns_answer answers[MAX_ANSWERS];
    // ----- 元数据 -----
    __u64 latency_ns;   // 解析延迟 (纳秒)
    // __u32 pid;
    // __u32 tgid;
    __u32 saddr;        // 客户端 IP
    __u32 daddr;        // DNS 服务器 IP
    __u16 sport;        // 客户端 端口
    __u16 dport;        // DNS 服务器 端口
    // ----- DNS 查询信息 (Question Section) -----
    __u16 tx_id;         // DNS 事务 ID
    __u16 qtype;         // 查询类型


    // ----- DNS 回复信息 (Answer Section) -----
    __u16 rcode;         // DNS响应码 (e.g., 0: NoError, 3: NXDomain)
    __u16 answer_count;  // 实际填充的 answer 数量
    // char comm[TASK_COMM_LEN];
} dns_event_t ;

#endif //DNS_LATENCY_H
