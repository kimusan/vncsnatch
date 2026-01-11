#include "network_utils.h"
#include "color_defs.h"
#include "misc_utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
/**
 * Computes the checksum of a packet.
 *
 * @param buf The buffer containing the packet data.
 * @param len The length of the buffer.
 * @return The computed checksum.
 */
unsigned short checksum(void *buf, int len) {
  unsigned short *buffer = buf;
  unsigned int sum = 0;
  unsigned short result;

  for (sum = 0; len > 1; len -= 2) {
    sum += *buffer++;
  }
  if (len == 1) {
    sum += *(unsigned char *)buffer;
  }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  result = ~sum;
  return result;
}

static int read_full(int fd, void *buf, size_t len) {
  size_t total = 0;
  char *p = buf;

  while (total < len) {
    ssize_t n = recv(fd, p + total, len - total, 0);
    if (n == 0) {
      return -1;
    }
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    total += (size_t)n;
  }

  return 0;
}

static int write_full(int fd, const void *buf, size_t len) {
  size_t total = 0;
  const char *p = buf;

  while (total < len) {
    ssize_t n = send(fd, p + total, len - total, 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    total += (size_t)n;
  }

  return 0;
}
/**
 * Checks if an IP address is reachable using ICMP echo requests.
 *
 * @param ip_addr The IP address to check.
 * @return true if the IP address is reachable, false otherwise.
 */
bool is_ip_up(const char *ip_addr) {
  if (!has_required_capabilities()) {
    return true;
  }

  int sockfd;
  struct sockaddr_in addr;
  struct icmp icmp_pkt;
  char recv_buf[1024];
  struct timeval timeout = {1, 0}; // 1 second timeout

  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd < 0) {
    perror(COLOR_RED "Socket creation failed" COLOR_RESET);
    return false;
  }

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(ip_addr);

  icmp_pkt.icmp_type = ICMP_ECHO;
  icmp_pkt.icmp_code = 0;
  icmp_pkt.icmp_id = getpid();
  icmp_pkt.icmp_seq = 0;
  icmp_pkt.icmp_cksum = 0;
  icmp_pkt.icmp_cksum = checksum(&icmp_pkt, sizeof(icmp_pkt));

  if (sendto(sockfd, &icmp_pkt, sizeof(icmp_pkt), 0, (struct sockaddr *)&addr,
             sizeof(addr)) <= 0) {
    perror(COLOR_RED "Sendto failed" COLOR_RESET);
    close(sockfd);
    return false;
  }

  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

  if (recv(sockfd, recv_buf, sizeof(recv_buf), 0) <= 0) {
    close(sockfd);
    return false;
  }

  close(sockfd);
  return true;
}

/**
 * Connects to a VNC server and checks the security type.
 *
 * @param tcp_ip The IP address of the VNC server.
 * @return 1 if no authentication is required, 0 if auth is required,
 * -1 on connection or protocol failure.
 */
int get_security(const char *tcp_ip, int port, bool verbose) {
  int result = -1;
  int vnc_socket;
  struct sockaddr_in server_addr;
  struct timeval timeout;
  char rfb_version[13];
  char rfb_version_send[12];
  unsigned char num_of_auth;
  unsigned char auth_type;
  int is_v33 = 0;
  if (verbose) {
    printf(COLOR_CYAN "   - Creating socket..." COLOR_RESET);
    fflush(stdout);
  }
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;

  vnc_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (vnc_socket < 0) {
    if (verbose) {
      printf(COLOR_RED "failed\n" COLOR_RESET);
    }
    return -1;
  }
  // lets try to make some more sane timeouts if possible.
  if (setsockopt(vnc_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                 sizeof timeout) < 0) {
    if (verbose) {
      printf("setsockopt failed\n");
    }
  }

  if (setsockopt(vnc_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                 sizeof timeout) < 0) {
    if (verbose) {
      printf("setsockopt failed\n");
    }
  }
  if (verbose) {
    printf(COLOR_GREEN "done\n" COLOR_RESET);
    fflush(stdout);
  }
  server_addr.sin_port = htons((uint16_t)port);
  server_addr.sin_family = AF_INET;
  if (inet_pton(AF_INET, tcp_ip, &server_addr.sin_addr) != 1) {
    if (verbose) {
      printf(COLOR_RED "failed\n" COLOR_RESET);
    }
    close(vnc_socket);
    return -1;
  }

  if (verbose) {
    printf(COLOR_CYAN "   - Creating connection..." COLOR_RESET);
    fflush(stdout);
  }
  if (connect(vnc_socket, (struct sockaddr *)&server_addr,
              sizeof(server_addr)) < 0) {
    if (verbose) {
      printf(COLOR_RED "failed\n" COLOR_RESET);
    }
    close(vnc_socket);
    return -1;
  }

  if (verbose) {
    printf(COLOR_GREEN "done\n" COLOR_RESET);
    printf(COLOR_CYAN "   - Getting RFB version..." COLOR_RESET);
    fflush(stdout);
  }
  if (read_full(vnc_socket, rfb_version, 12) < 0) {
    if (verbose) {
      printf(COLOR_RED "failed\n" COLOR_RESET);
    }
    close(vnc_socket);
    return -1;
  }
  memcpy(rfb_version_send, rfb_version, sizeof(rfb_version_send));
  rfb_version[12] = '\0';
  if (verbose) {
    fflush(stdout);
  }
  if (strstr(rfb_version, "RFB") == NULL) {
    close(vnc_socket);
    if (verbose) {
      printf(COLOR_RED "failed\n" COLOR_RESET);
    }
    return -1;
  } else {
    rfb_version[strcspn(rfb_version, "\n")] = '\0';
    if (verbose) {
      printf("[%s]..", rfb_version);
    }
  }
  if (strncmp(rfb_version, "RFB 003.003", 11) == 0) {
    is_v33 = 1;
  }

  if (verbose) {
    printf(COLOR_GREEN "done\n" COLOR_RESET);
    printf(COLOR_CYAN "   - Getting auth type..." COLOR_RESET);
    fflush(stdout);
  }
  if (write_full(vnc_socket, rfb_version_send, sizeof(rfb_version_send)) < 0) {
    if (verbose) {
      printf(COLOR_RED "failed\n" COLOR_RESET);
    }
    close(vnc_socket);
    return -1;
  }

  if (is_v33) {
    uint32_t auth_type32 = 0;
    if (read_full(vnc_socket, &auth_type32, sizeof(auth_type32)) < 0) {
      if (verbose) {
        printf(COLOR_RED "failed\n" COLOR_RESET);
      }
      close(vnc_socket);
      return -1;
    }
    auth_type32 = ntohl(auth_type32);
    if (auth_type32 == 0) {
      close(vnc_socket);
      return -1;
    }
    result = auth_type32 == 1 ? 1 : 0;
    if (auth_type32 == 1 && verbose) {
      printf(COLOR_CYAN "[no auth]..." COLOR_RESET);
    }
  } else {
    if (read_full(vnc_socket, &num_of_auth, 1) < 0) {
      if (verbose) {
        printf(COLOR_RED "failed\n" COLOR_RESET);
      }
      close(vnc_socket);
      return -1;
    }
    if (num_of_auth == 0) {
      uint32_t reason_len = 0;
      if (read_full(vnc_socket, &reason_len, sizeof(reason_len)) < 0) {
        if (verbose) {
          printf(COLOR_RED "failed\n" COLOR_RESET);
        }
        close(vnc_socket);
        return -1;
      }
      reason_len = ntohl(reason_len);
      if (reason_len > 0) {
        char *reason = malloc(reason_len + 1);
        if (reason) {
          if (read_full(vnc_socket, reason, reason_len) == 0) {
            reason[reason_len] = '\0';
          }
          free(reason);
        }
      }
      if (verbose) {
        printf(COLOR_RED "failed\n" COLOR_RESET);
      }
      close(vnc_socket);
      return -1;
    }

    result = 0;
    for (unsigned int i = 0; i < num_of_auth; i++) {
      if (read_full(vnc_socket, &auth_type, 1) < 0) {
        if (verbose) {
          printf(COLOR_RED "failed\n" COLOR_RESET);
        }
        close(vnc_socket);
        return -1;
      }
      if (auth_type == 1) {
        result = 1;
        if (verbose) {
          printf(COLOR_CYAN "[no auth]..." COLOR_RESET);
        }
      } else {
        if (verbose) {
          printf(COLOR_CYAN "." COLOR_RESET);
        }
      }
    }
  }
  if (verbose) {
    printf(COLOR_GREEN "done\n" COLOR_RESET);
    printf(COLOR_CYAN "   - Closing socket..." COLOR_RESET);
    fflush(stdout);
  }
  shutdown(vnc_socket, SHUT_WR);
  close(vnc_socket);
  if (verbose) {
    printf(COLOR_GREEN "done\n" COLOR_RESET);
  }
  return result;
}
