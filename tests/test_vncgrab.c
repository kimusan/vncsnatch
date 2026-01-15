#include "vncgrab.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 4 || argc > 10) {
    fprintf(stderr,
            "Usage: %s <host> <port> <outfile> [password] [rect] [allowblank]\n",
            argv[0]);
    return 2;
  }

  const char *host = argv[1];
  int port = atoi(argv[2]);
  const char *outfile = argv[3];
  const char *password = NULL;
  int rect_x = -1;
  int rect_y = -1;
  int rect_w = 0;
  int rect_h = 0;
  int allow_blank = 1;
  int arg_index = 4;
  if (argc > arg_index && argv[arg_index][0] != '\0') {
    password = argv[arg_index];
  }
  arg_index++;
  if (argc > arg_index && argv[arg_index][0] != '\0') {
    if (sscanf(argv[arg_index], "%dx%d+%d+%d",
               &rect_w, &rect_h, &rect_x, &rect_y) != 4) {
      fprintf(stderr, "Invalid rect format\n");
      return 2;
    }
  }
  arg_index++;
  if (argc > arg_index && argv[arg_index][0] != '\0') {
    if (atoi(argv[arg_index]) == 0) {
      allow_blank = 0;
    }
  }

  int result = vncgrab_snapshot(host, port, password, outfile, 5, allow_blank,
                                90, rect_x, rect_y, rect_w, rect_h, false);
  if (result != 0) {
    fprintf(stderr, "vncgrab_snapshot failed\n");
    return 1;
  }

  if (access(outfile, F_OK) != 0) {
    fprintf(stderr, "Output file not found\n");
    return 1;
  }

  return 0;
}
