#include "color_defs.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <unistd.h>
/**
 * Checks if the program has the necessary capabilities or is run by root.
 *
 * @return true if the program has the required capabilities or is run by root,
 * false otherwise.
 */
bool has_required_capabilities() {
  if (geteuid() == 0) {
    return true;
  }

  cap_t caps = cap_get_proc();
  if (caps == NULL) {
    perror(COLOR_RED "Failed to get capabilities" COLOR_RESET);
    return false;
  }

  cap_flag_value_t cap_net_admin, cap_net_raw;
  cap_get_flag(caps, CAP_NET_ADMIN, CAP_EFFECTIVE, &cap_net_admin);
  cap_get_flag(caps, CAP_NET_RAW, CAP_EFFECTIVE, &cap_net_raw);
  cap_free(caps);

  return (cap_net_admin == CAP_SET && cap_net_raw == CAP_SET);
}
