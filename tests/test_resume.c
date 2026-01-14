#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_resume_offset(const char *path, const char *country_code,
                              unsigned long long *offset_out,
                              unsigned long long *online_out,
                              unsigned long long *vnc_out,
                              unsigned long long *noauth_out,
                              unsigned long long *auth_success_out,
                              unsigned long long *auth_attempts_out) {
  FILE *file = fopen(path, "r");
  if (!file) {
    return -1;
  }
  char line[128];
  unsigned long long value = 0;
  unsigned long long online = 0;
  unsigned long long vnc = 0;
  unsigned long long noauth = 0;
  unsigned long long auth_success = 0;
  unsigned long long auth_attempts = 0;
  if (!fgets(line, sizeof(line), file)) {
    fclose(file);
    return -1;
  }
  char stored_country[8] = {0};
  if (sscanf(line, "%7s %llu %llu %llu %llu %llu %llu", stored_country, &value,
             &online, &vnc, &noauth, &auth_success, &auth_attempts) >= 2) {
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
  if (online_out) {
    *online_out = online;
  }
  if (vnc_out) {
    *vnc_out = vnc;
  }
  if (noauth_out) {
    *noauth_out = noauth;
  }
  if (auth_success_out) {
    *auth_success_out = auth_success;
  }
  if (auth_attempts_out) {
    *auth_attempts_out = auth_attempts;
  }
  return 0;
}

int main() {
  unsigned long long value = 0;
  unsigned long long online = 0;
  unsigned long long vnc = 0;
  unsigned long long noauth = 0;
  unsigned long long auth_success = 0;
  unsigned long long auth_attempts = 0;

  FILE *file = fopen("tests/tmp_resume.txt", "w");
  if (!file) {
    return 1;
  }
  fprintf(file, "SE 123 4 5 6 7 8\n");
  fclose(file);

  if (read_resume_offset("tests/tmp_resume.txt", "SE", &value, &online, &vnc,
                         &noauth, &auth_success, &auth_attempts) != 0 ||
      value != 123ULL || online != 4ULL || vnc != 5ULL || noauth != 6ULL ||
      auth_success != 7ULL || auth_attempts != 8ULL) {
    fprintf(stderr, "country match failed\n");
    return 1;
  }
  if (read_resume_offset("tests/tmp_resume.txt", "DK", &value, &online, &vnc,
                         &noauth, &auth_success, &auth_attempts) == 0) {
    fprintf(stderr, "country mismatch should fail\n");
    return 1;
  }

  file = fopen("tests/tmp_resume.txt", "w");
  if (!file) {
    return 1;
  }
  fprintf(file, "456\n");
  fclose(file);
  if (read_resume_offset("tests/tmp_resume.txt", "SE", &value, &online, &vnc,
                         &noauth, &auth_success, &auth_attempts) != 0 ||
      value != 456ULL) {
    fprintf(stderr, "numeric fallback failed\n");
    return 1;
  }

  remove("tests/tmp_resume.txt");
  return 0;
}
