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
                            int verbose, const char *password);
static int parse_ports(const char *arg, int *ports, size_t max_ports);
static int parse_rect(const char *arg, int *x, int *y, int *w, int *h);

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
  uint64_t screenshots;
  int snapshot_timeout;
  int verbose;
  int quiet;
  const char *password;
  int allow_blank;
  int jpeg_quality;
  int rect_x;
  int rect_y;
  int rect_w;
  int rect_h;
  int ports[8];
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
                               uint64_t *total_ips_out) {
  FILE *file = fopen(file_location, "r");
  char line[1024];
  ip_range_t *ranges = NULL;
  size_t range_count = 0;
  size_t range_capacity = 0;
  uint64_t total_ips = 0;

  if (file == NULL) {
    perror(COLOR_RED "Failed to open CSV file" COLOR_RESET);
    return -1;
  }

  while (fgets(line, sizeof(line), file) != NULL) {
    char start_ip_str[20], end_ip_str[20], csv_country_code[3],
        country_name[50];
    int parsed = sscanf(line, "\"%19[^\"]\",\"%19[^\"]\",\"%2[^\"]\",\"%49[^\"]\"",
                        start_ip_str, end_ip_str, csv_country_code,
                        country_name);
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
  pthread_mutex_unlock(&ctx->stats_mutex);

  double pct = total ? (double)scanned * 100.0 / (double)total : 0.0;
  printf("\r\033[2KProgress: %llu/%llu (%.1f%%) online:%llu vnc:%llu noauth:%llu shots:%llu",
         (unsigned long long)scanned,
         (unsigned long long)total,
         pct,
         (unsigned long long)online,
         (unsigned long long)vnc_found,
         (unsigned long long)vnc_noauth,
         (unsigned long long)shots);
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

    int online = is_ip_up(ip_addr);
    int vnc_state = -1;
    int took_shot = 0;

    if (online) {
      int port_used = 0;
      for (size_t i = 0; i < ctx->port_count; i++) {
        vnc_state = get_security(ip_addr, ctx->ports[i], ctx->verbose != 0);
        if (vnc_state >= 0) {
          port_used = ctx->ports[i];
          break;
        }
      }
      if ((vnc_state == 1 ||
           (vnc_state == 0 && ctx->password != NULL)) &&
          capture_snapshot(ip_addr, port_used, ctx->snapshot_timeout,
                           ctx->verbose, ctx->password, ctx->allow_blank,
                           ctx->jpeg_quality, ctx->rect_x, ctx->rect_y,
                           ctx->rect_w, ctx->rect_h) == 0) {
        took_shot = 1;
      }
    } else if (ctx->verbose) {
      pthread_mutex_lock(&ctx->print_mutex);
      printf("not online. Skipping!\n");
      pthread_mutex_unlock(&ctx->print_mutex);
    }

    pthread_mutex_lock(&ctx->stats_mutex);
    ctx->scanned_ips++;
    if (online) {
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
                        int rate_limit, const char *password, int allow_blank,
                        int jpeg_quality, int rect_x, int rect_y, int rect_w,
                        int rect_h) {
  ip_range_t *ranges = NULL;
  size_t range_count = 0;
  uint64_t total_ips = 0;

  if (load_country_ranges(file_location, country_code, &ranges, &range_count,
                          &total_ips) != 0) {
    return 0;
  }

  if (range_count == 0) {
    printf(COLOR_YELLOW "No ranges found for country code %s.\n" COLOR_RESET,
           country_code);
    free(ranges);
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
  ctx.password = password;
  ctx.allow_blank = allow_blank;
  ctx.jpeg_quality = jpeg_quality;
  ctx.rect_x = rect_x;
  ctx.rect_y = rect_y;
  ctx.rect_w = rect_w;
  ctx.rect_h = rect_h;
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
  if (!quiet) {
    printf("Using %d worker threads\n", worker_count);
  }
  update_progress(&ctx, 1);

  pthread_t *threads = calloc((size_t)worker_count, sizeof(*threads));
  if (!threads) {
    free(ranges);
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
  free(threads);
  free(ranges);
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
  int allow_blank = 0;
  int jpeg_quality = 100;
  int rect_x = -1;
  int rect_y = -1;
  int rect_w = 0;
  int rect_h = 0;
  int ports[8] = {5900, 5901};
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
  while ((opt = getopt_long(argc, argv, "c:f:w:t:p:rR:P:bBQ:x:vqh",
                            &option_index)) != -1) {
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
                                      rate_limit, password, allow_blank,
                                      jpeg_quality, rect_x, rect_y, rect_w,
                                      rect_h);
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
  return 0;
}
