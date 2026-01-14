
#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <stdbool.h>

#define TCP_PORT 5900

unsigned short checksum(void *buf, int len);
bool is_ip_up(const char *ip_addr);
int is_tcp_open(const char *ip_addr, int port, int timeout_ms);
int get_security(const char *tcp_ip, int port, bool verbose);

#endif // NETWORK_UTILS_H
