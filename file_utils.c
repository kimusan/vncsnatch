
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/**
 * Cleans the file path by trimming whitespace and removing escape characters.
 *
 * @param file_location The original file path.
 * @return A cleaned version of the file path.
 */

char *clean_file_location(char *s) {
  size_t size;
  char *end;

  size = strlen(s);

  if (!size)
    return s;

  end = s + size - 1;
  while (end >= s && isspace(*end))
    end--;
  *(end + 1) = '\0';

  while (*s && isspace(*s))
    s++;

  return s;
}
