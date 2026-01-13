#include "vncgrab.h"
#include <arpa/inet.h>
#include <errno.h>
#include <jpeglib.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef USE_OPENSSL
#include <openssl/des.h>
#endif

typedef struct {
  uint8_t bits_per_pixel;
  uint8_t depth;
  uint8_t big_endian;
  uint8_t true_color;
  uint16_t red_max;
  uint16_t green_max;
  uint16_t blue_max;
  uint8_t red_shift;
  uint8_t green_shift;
  uint8_t blue_shift;
  uint8_t pad[3];
} pixel_format_t;

static int read_full(int fd, void *buf, size_t len) {
  size_t total = 0;
  uint8_t *p = buf;

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
  const uint8_t *p = buf;

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

static int set_timeouts(int fd, int timeout_sec) {
  struct timeval timeout;
  timeout.tv_sec = timeout_sec;
  timeout.tv_usec = 0;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
    return -1;
  }
  if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
    return -1;
  }
  return 0;
}

static int write_jpeg(const char *path, int width, int height,
                      const uint8_t *rgb) {
  struct jpeg_compress_struct cinfo;
  struct jpeg_error_mgr jerr;
  FILE *outfile = fopen(path, "wb");
  if (!outfile) {
    return -1;
  }

  cinfo.err = jpeg_std_error(&jerr);
  jpeg_create_compress(&cinfo);
  jpeg_stdio_dest(&cinfo, outfile);

  cinfo.image_width = width;
  cinfo.image_height = height;
  cinfo.input_components = 3;
  cinfo.in_color_space = JCS_RGB;

  jpeg_set_defaults(&cinfo);
  jpeg_set_quality(&cinfo, 90, TRUE);
  jpeg_start_compress(&cinfo, TRUE);

  while (cinfo.next_scanline < cinfo.image_height) {
    JSAMPROW row_ptr =
        (JSAMPROW)&rgb[cinfo.next_scanline * (size_t)width * 3];
    jpeg_write_scanlines(&cinfo, &row_ptr, 1);
  }

  jpeg_finish_compress(&cinfo);
  jpeg_destroy_compress(&cinfo);
  fclose(outfile);
  return 0;
}

static int is_blank_frame(const uint8_t *rgb, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (rgb[i] != 0) {
      return 0;
    }
  }
  return 1;
}

static uint8_t reverse_bits(uint8_t value) {
  value = (uint8_t)((value & 0xF0) >> 4 | (value & 0x0F) << 4);
  value = (uint8_t)((value & 0xCC) >> 2 | (value & 0x33) << 2);
  value = (uint8_t)((value & 0xAA) >> 1 | (value & 0x55) << 1);
  return value;
}

static int read_security_result(int fd) {
  uint32_t status = 0;
  if (read_full(fd, &status, sizeof(status)) < 0) {
    return -1;
  }
  status = ntohl(status);
  if (status != 0) {
    uint32_t reason_len = 0;
    if (read_full(fd, &reason_len, sizeof(reason_len)) == 0) {
      reason_len = ntohl(reason_len);
      if (reason_len > 0) {
        char *reason = malloc(reason_len + 1);
        if (reason) {
          if (read_full(fd, reason, reason_len) == 0) {
            reason[reason_len] = '\0';
          }
          free(reason);
        }
      }
    }
    return -1;
  }
  return 0;
}

static int vnc_authenticate(int fd, const char *password) {
  uint8_t challenge[16];
  if (read_full(fd, challenge, sizeof(challenge)) < 0) {
    return -1;
  }

#ifdef USE_OPENSSL
  uint8_t key_bytes[8] = {0};
  size_t pass_len = strlen(password);
  for (size_t i = 0; i < 8 && i < pass_len; i++) {
    key_bytes[i] = reverse_bits((uint8_t)password[i]);
  }

  DES_cblock key;
  DES_key_schedule schedule;
  memcpy(key, key_bytes, sizeof(key));
  DES_set_key_unchecked(&key, &schedule);

  uint8_t response[16];
  DES_ecb_encrypt((const_DES_cblock *)challenge, (DES_cblock *)response,
                  &schedule, DES_ENCRYPT);
  DES_ecb_encrypt((const_DES_cblock *)(challenge + 8),
                  (DES_cblock *)(response + 8), &schedule, DES_ENCRYPT);

  if (write_full(fd, response, sizeof(response)) < 0) {
    return -1;
  }

  return read_security_result(fd);
#else
  (void)password;
  return -1;
#endif
}

int vncgrab_snapshot(const char *ip, int port, const char *password,
                     const char *out_path, int timeout_sec, bool allow_blank,
                     bool verbose) {
  int fd = -1;
  int result = -1;
  uint8_t *raw = NULL;
  uint8_t *rgb = NULL;

  if (!ip || !out_path || port <= 0 || port > 65535) {
    return -1;
  }

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }
  if (set_timeouts(fd, timeout_sec) < 0) {
    close(fd);
    return -1;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
    close(fd);
    return -1;
  }

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(fd);
    return -1;
  }

  char server_version[12];
  if (read_full(fd, server_version, sizeof(server_version)) < 0) {
    close(fd);
    return -1;
  }
  if (memcmp(server_version, "RFB", 3) != 0) {
    close(fd);
    return -1;
  }

  int is_v33 = memcmp(server_version + 4, "003.003", 7) == 0;
  const char *client_version = is_v33 ? "RFB 003.003\n" : "RFB 003.008\n";
  if (write_full(fd, client_version, 12) < 0) {
    close(fd);
    return -1;
  }

  if (is_v33) {
    uint32_t sec_type = 0;
    if (read_full(fd, &sec_type, sizeof(sec_type)) < 0) {
      close(fd);
      return -1;
    }
    sec_type = ntohl(sec_type);
    if (sec_type == 0) {
      close(fd);
      return -1;
    }
    if (sec_type == 1) {
      /* no auth */
    } else if (sec_type == 2) {
      if (!password) {
        close(fd);
        return -1;
      }
      if (vnc_authenticate(fd, password) < 0) {
        close(fd);
        return -1;
      }
    } else {
      close(fd);
      return -1;
    }
  } else {
    uint8_t sec_count = 0;
    if (read_full(fd, &sec_count, 1) < 0) {
      close(fd);
      return -1;
    }
    if (sec_count == 0) {
      read_security_result(fd);
      close(fd);
      return -1;
    }
    uint8_t types[32];
    if (sec_count > sizeof(types)) {
      close(fd);
      return -1;
    }
    if (read_full(fd, types, sec_count) < 0) {
      close(fd);
      return -1;
    }

    uint8_t selected = 0;
    for (uint8_t i = 0; i < sec_count; i++) {
      if (types[i] == 1) {
        selected = 1;
        break;
      }
    }
    if (password) {
      for (uint8_t i = 0; i < sec_count; i++) {
        if (types[i] == 2) {
          selected = 2;
          break;
        }
      }
    }
    if (selected == 0) {
      close(fd);
      return -1;
    }
    if (write_full(fd, &selected, 1) < 0) {
      close(fd);
      return -1;
    }
    if (selected == 1) {
      if (read_security_result(fd) < 0) {
        close(fd);
        return -1;
      }
    } else if (selected == 2) {
      if (!password) {
        close(fd);
        return -1;
      }
      if (vnc_authenticate(fd, password) < 0) {
        close(fd);
        return -1;
      }
    }
  }

  uint8_t client_init = 1;
  if (write_full(fd, &client_init, 1) < 0) {
    close(fd);
    return -1;
  }

  uint8_t init_buf[24];
  if (read_full(fd, init_buf, sizeof(init_buf)) < 0) {
    close(fd);
    return -1;
  }

  uint16_t width = (uint16_t)((init_buf[0] << 8) | init_buf[1]);
  uint16_t height = (uint16_t)((init_buf[2] << 8) | init_buf[3]);
  uint32_t name_len = (uint32_t)((init_buf[20] << 24) | (init_buf[21] << 16) |
                                 (init_buf[22] << 8) | init_buf[23]);
  if (name_len > 0) {
    char *name = malloc(name_len + 1);
    if (name) {
      if (read_full(fd, name, name_len) == 0) {
        name[name_len] = '\0';
      }
      free(name);
    } else {
      uint8_t discard[256];
      while (name_len > 0) {
        size_t chunk = name_len > sizeof(discard) ? sizeof(discard) : name_len;
        if (read_full(fd, discard, chunk) < 0) {
          close(fd);
          return -1;
        }
        name_len -= (uint32_t)chunk;
      }
    }
  }

  pixel_format_t pf;
  memset(&pf, 0, sizeof(pf));
  pf.bits_per_pixel = 32;
  pf.depth = 24;
  pf.big_endian = 0;
  pf.true_color = 1;
  pf.red_max = htons(255);
  pf.green_max = htons(255);
  pf.blue_max = htons(255);
  pf.red_shift = 16;
  pf.green_shift = 8;
  pf.blue_shift = 0;

  uint8_t set_pf[20];
  memset(set_pf, 0, sizeof(set_pf));
  set_pf[0] = 0;
  memcpy(set_pf + 4, &pf, sizeof(pf));
  if (write_full(fd, set_pf, sizeof(set_pf)) < 0) {
    close(fd);
    return -1;
  }

  uint8_t set_enc[8];
  memset(set_enc, 0, sizeof(set_enc));
  set_enc[0] = 2;
  set_enc[2] = 0;
  set_enc[3] = 1;
  uint32_t enc_raw = htonl(0);
  memcpy(set_enc + 4, &enc_raw, sizeof(enc_raw));
  if (write_full(fd, set_enc, sizeof(set_enc)) < 0) {
    close(fd);
    return -1;
  }

  uint8_t fb_req[10];
  memset(fb_req, 0, sizeof(fb_req));
  fb_req[0] = 3;
  fb_req[1] = 0;
  fb_req[6] = (uint8_t)(width >> 8);
  fb_req[7] = (uint8_t)(width & 0xFF);
  fb_req[8] = (uint8_t)(height >> 8);
  fb_req[9] = (uint8_t)(height & 0xFF);
  if (write_full(fd, fb_req, sizeof(fb_req)) < 0) {
    close(fd);
    return -1;
  }

  uint8_t msg_type = 0;
  if (read_full(fd, &msg_type, 1) < 0) {
    close(fd);
    return -1;
  }
  if (msg_type != 0) {
    close(fd);
    return -1;
  }
  uint8_t padding = 0;
  uint16_t rect_count = 0;
  if (read_full(fd, &padding, 1) < 0 ||
      read_full(fd, &rect_count, sizeof(rect_count)) < 0) {
    close(fd);
    return -1;
  }
  rect_count = ntohs(rect_count);
  if (rect_count == 0) {
    close(fd);
    return -1;
  }

  size_t rgb_len = (size_t)width * (size_t)height * 3;
  rgb = malloc(rgb_len);
  if (!rgb) {
    close(fd);
    return -1;
  }
  memset(rgb, 0, rgb_len);

  for (uint16_t r = 0; r < rect_count; r++) {
    uint8_t rect_hdr[12];
    if (read_full(fd, rect_hdr, sizeof(rect_hdr)) < 0) {
      goto cleanup;
    }
    uint16_t rx = (uint16_t)((rect_hdr[0] << 8) | rect_hdr[1]);
    uint16_t ry = (uint16_t)((rect_hdr[2] << 8) | rect_hdr[3]);
    uint16_t rw = (uint16_t)((rect_hdr[4] << 8) | rect_hdr[5]);
    uint16_t rh = (uint16_t)((rect_hdr[6] << 8) | rect_hdr[7]);
    int32_t encoding = (int32_t)((rect_hdr[8] << 24) | (rect_hdr[9] << 16) |
                                 (rect_hdr[10] << 8) | rect_hdr[11]);
    if (encoding != 0) {
      goto cleanup;
    }

    size_t raw_len = (size_t)rw * (size_t)rh * 4;
    raw = malloc(raw_len);
    if (!raw) {
      goto cleanup;
    }
    if (read_full(fd, raw, raw_len) < 0) {
      goto cleanup;
    }

    for (uint16_t y = 0; y < rh; y++) {
      for (uint16_t x = 0; x < rw; x++) {
        size_t src = ((size_t)y * rw + x) * 4;
        uint32_t value = (uint32_t)raw[src] |
                         ((uint32_t)raw[src + 1] << 8) |
                         ((uint32_t)raw[src + 2] << 16) |
                         ((uint32_t)raw[src + 3] << 24);
        uint8_t r8 = (uint8_t)((value >> pf.red_shift) & 0xFF);
        uint8_t g8 = (uint8_t)((value >> pf.green_shift) & 0xFF);
        uint8_t b8 = (uint8_t)((value >> pf.blue_shift) & 0xFF);
        size_t dst = ((size_t)(ry + y) * width + (rx + x)) * 3;
        if (dst + 2 < rgb_len) {
          rgb[dst] = r8;
          rgb[dst + 1] = g8;
          rgb[dst + 2] = b8;
        }
      }
    }
    free(raw);
    raw = NULL;
  }

  if (!allow_blank && is_blank_frame(rgb, rgb_len)) {
    goto cleanup;
  }

  if (write_jpeg(out_path, width, height, rgb) < 0) {
    goto cleanup;
  }

  if (verbose) {
    fprintf(stderr, "Saved snapshot %s (%ux%u)\n", out_path, width, height);
  }
  result = 0;

cleanup:
  if (raw) {
    free(raw);
  }
  if (rgb) {
    free(rgb);
  }
  if (fd >= 0) {
    close(fd);
  }
  return result;
}
