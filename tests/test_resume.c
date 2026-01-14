#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_resume_offset(const char *path, const char *country_code,
                              unsigned long long *offset_out) {
  FILE *file = fopen(path, "r");
  if (!file) {
    return -1;
  }
  char line[128];
  unsigned long long value = 0;
  if (!fgets(line, sizeof(line), file)) {
    fclose(file);
    return -1;
  }
  char stored_country[8] = {0};
  if (sscanf(line, "%7s %llu", stored_country, &value) == 2) {
    if (!country_code || strcmp(stored_country, country_code) != 0) {
      fclose(file);
      return -1;
    }
  } else if (sscanf(line, "%llu", &value) != 1) {
    fclose(file);
    return -1;
  }
  fclose(file);
  *offset_out = value;
  return 0;
}

int main() {
  unsigned long long value = 0;

  FILE *file = fopen("tests/tmp_resume.txt", "w");
  if (!file) {
    return 1;
  }
  fprintf(file, "SE 123\n");
  fclose(file);

  if (read_resume_offset("tests/tmp_resume.txt", "SE", &value) != 0 ||
      value != 123ULL) {
    fprintf(stderr, "country match failed\n");
    return 1;
  }
  if (read_resume_offset("tests/tmp_resume.txt", "DK", &value) == 0) {
    fprintf(stderr, "country mismatch should fail\n");
    return 1;
  }

  file = fopen("tests/tmp_resume.txt", "w");
  if (!file) {
    return 1;
  }
  fprintf(file, "456\n");
  fclose(file);
  if (read_resume_offset("tests/tmp_resume.txt", "SE", &value) != 0 ||
      value != 456ULL) {
    fprintf(stderr, "numeric fallback failed\n");
    return 1;
  }

  remove("tests/tmp_resume.txt");
  return 0;
}
