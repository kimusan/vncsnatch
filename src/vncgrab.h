#ifndef VNCGRAB_H
#define VNCGRAB_H

#include <stdbool.h>

int vncgrab_snapshot(const char *ip, int port, const char *password,
                     const char *out_path, int timeout_sec, bool allow_blank,
                     int jpeg_quality, int rect_x, int rect_y, int rect_w,
                     int rect_h, bool verbose);

#endif // VNCGRAB_H
