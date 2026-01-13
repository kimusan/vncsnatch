#include "vncgrab.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 4 || argc > 5) {
    fprintf(stderr, "Usage: %s <host> <port> <outfile> [password]\n", argv[0]);
    return 2;
  }

  const char *host = argv[1];
  int port = atoi(argv[2]);
  const char *outfile = argv[3];
  const char *password = NULL;
  if (argc == 5) {
    password = argv[4];
  }

  int result =
      vncgrab_snapshot(host, port, password, outfile, 2, true, false);
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
