
#ifndef FILE_UTILS_H
#define FILE_UTILS_H

/**
 * Cleans the file path by trimming whitespace and removing escape characters.
 *
 * @param file_location The original file path.
 * @return A cleaned version of the file path.
 */
char *clean_file_location(char *file_location);

#endif // FILE_UTILS_H
