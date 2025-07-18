//
// Created by syb on 25-7-7.
//

#ifndef UTILS_H
#define UTILS_H
#include <string>
#include <arpa/inet.h>
#include <cstring>
// --- 辅助函数 ---
// 将 C 风格的 null-terminated 字节数组转换为 C++ 字符串
inline std::string bytes_to_string(const char* buffer, size_t max_len) {
    size_t len = strnlen(buffer, max_len);
    return {buffer,len};
}

// 将 IPv4 整数转换为字符串
inline std::string ipv4_to_string(uint32_t ip_int) {
    struct in_addr addr{};
    addr.s_addr = ip_int;
    return inet_ntoa(addr);
}

// 将 IPv6 数组转换为字符串
inline std::string ipv6_to_string(const uint32_t ip_arr[4]) {
    char str[INET6_ADDRSTRLEN];
    struct in6_addr addr{};
    memcpy(&addr, ip_arr, sizeof(addr));
    inet_ntop(AF_INET6, &addr, str, INET6_ADDRSTRLEN);
    return str;
}
inline  uint64_t getTimestampMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}
#endif //UTILS_H
