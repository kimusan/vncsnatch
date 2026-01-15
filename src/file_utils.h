
#ifndef FILE_UTILS_H
#define FILE_UTILS_H

/**
 * Cleans the file path by trimming whitespace and removing escape characters.
 *
 * @param file_location The original file path.
 * @return A newly allocated cleaned file path, or NULL on failure.
 */
char *clean_file_location(const char *file_location);

#endif // FILE_UTILS_H
