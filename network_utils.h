
#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <stdbool.h>

#define TCP_PORT 5900

unsigned short checksum(void *buf, int len);
bool is_ip_up(const char *ip_addr);
int get_security(const char *tcp_ip, bool verbose);

#endif // NETWORK_UTILS_H
