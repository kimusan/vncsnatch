#include "network_utils.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc < 4 || argc > 5) {
    fprintf(stderr, "Usage: %s <host> <port> <expected> [verbose]\n", argv[0]);
    return 2;
  }

  const char *host = argv[1];
  int port = atoi(argv[2]);
  int expected = atoi(argv[3]);

  int verbose = 0;
  if (argc == 5) {
    verbose = atoi(argv[4]);
  }

  int result = get_security(host, port, verbose);
  if (result != expected) {
    fprintf(stderr, "Expected %d, got %d\n", expected, result);
    return 1;
  }

  return 0;
}
