
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/**
 * Cleans the file path by trimming whitespace and removing escape characters.
 *
 * @param file_location The original file path.
 * @return A newly allocated cleaned file path, or NULL on failure.
 */
char *clean_file_location(const char *s) {
  const char *start;
  const char *end;
  size_t len;
  char *cleaned;

  if (!s) {
    return NULL;
  }

  start = s;
  while (*start && isspace((unsigned char)*start)) {
    start++;
  }

  end = s + strlen(s);
  while (end > start && isspace((unsigned char)*(end - 1))) {
    end--;
  }

  len = (size_t)(end - start);
  cleaned = malloc(len + 1);
  if (!cleaned) {
    return NULL;
  }

  memcpy(cleaned, start, len);
  cleaned[len] = '\0';
  return cleaned;
}
