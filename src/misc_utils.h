
#ifndef MISC_UTILS_H
#define MISC_UTILS_H

#include <stdbool.h>

/**
 * Checks if the program has the necessary capabilities or is run by root.
 *
 * @return true if the program has the required capabilities or is run by root,
 * false otherwise.
 */
bool has_required_capabilities();

#endif // MISC_UTILS_H
