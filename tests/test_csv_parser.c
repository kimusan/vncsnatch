/*
 * Unit tests for the IP-to-country CSV parser.
 *
 * The parser functions below are kept in sync with their definitions in
 * src/vncsnatch.c (same approach as test_resume.c). They are self-contained so
 * the test builds without linking the scanner's threading/readline/jpeg deps.
 *
 * Covered layouts:
 *   - IP2Location LITE DB1:  "from","to","CC","Country Name" (quoted decimal)
 *   - sapics/ip-location-db: from,to,CC                      (dotted, no name)
 *   - datasets/geoip2-ipv4:  CIDR,geoname,...,CC,Country,... (CIDR + columns)
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/*
 * Converts a textual IPv4 value to a host-order uint32.
 *
 * Accepts both representations seen in public country databases:
 *   - IP2Location style decimal integer (e.g. "16777216")
 *   - dotted-quad (e.g. "1.0.0.0"), used by GitHub mirrors such as
 *     sapics/ip-location-db
 *
 * Returns 0 on success and writes the value to *out, or -1 if the string is
 * not a valid IPv4 value in either form.
 */
static int parse_ipv4_value(const char *str, uint32_t *out) {
  if (str == NULL || *str == '\0') {
    return -1;
  }
  if (strchr(str, '.') != NULL) {
    struct in_addr addr;
    if (inet_pton(AF_INET, str, &addr) != 1) {
      return -1;
    }
    *out = ntohl(addr.s_addr);
    return 0;
  }
  char *endptr = NULL;
  errno = 0;
  unsigned long long value = strtoull(str, &endptr, 10);
  if (errno != 0 || endptr == str || *endptr != '\0' || value > UINT32_MAX) {
    return -1;
  }
  *out = (uint32_t)value;
  return 0;
}

/*
 * Expands an IPv4 CIDR block (e.g. "1.0.0.0/24") into its first and last
 * address. A bare address with no "/" is treated as a single-host /32.
 *
 * Returns 0 on success, -1 on malformed input.
 */
static int parse_ipv4_cidr(const char *str, uint32_t *start_out,
                           uint32_t *end_out) {
  char buf[46];
  snprintf(buf, sizeof(buf), "%s", str);
  char *slash = strchr(buf, '/');
  int prefix = 32;
  if (slash) {
    *slash = '\0';
    char *endptr = NULL;
    errno = 0;
    long p = strtol(slash + 1, &endptr, 10);
    if (errno != 0 || endptr == slash + 1 || *endptr != '\0' || p < 0 ||
        p > 32) {
      return -1;
    }
    prefix = (int)p;
  }
  uint32_t base;
  if (parse_ipv4_value(buf, &base) != 0) {
    return -1;
  }
  uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
  *start_out = base & mask;
  *end_out = base | ~mask;
  return 0;
}

/*
 * Splits a CSV line into fields on commas, honouring simple double-quoting.
 * Surrounding quotes are stripped and a trailing CR/LF is trimmed from the
 * last field. Returns the number of fields stored (capped at max_fields).
 */
static size_t split_csv(const char *line, char fields[][128], size_t max_fields) {
  size_t count = 0;
  const char *p = line;
  while (count < max_fields) {
    char *out = fields[count];
    size_t len = 0;
    int in_quotes = 0;
    if (*p == '"') {
      in_quotes = 1;
      p++;
    }
    while (*p && len + 1 < 128) {
      if (in_quotes) {
        if (*p == '"') { p++; break; }
      } else if (*p == ',' || *p == '\r' || *p == '\n') {
        break;
      }
      out[len++] = *p++;
    }
    out[len] = '\0';
    count++;
    /* Advance to the next field separator. */
    while (*p && *p != ',' && *p != '\r' && *p != '\n') {
      p++;
    }
    if (*p != ',') {
      break;
    }
    p++;
  }
  return count;
}

/* An exact two-uppercase-letter token, e.g. "US" (not "USA" or "Us"). */
static int is_country_code_token(const char *s) {
  return s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z' &&
         s[2] == '\0';
}

/*
 * Parses a single CSV line into a range for the requested country.
 *
 * Supports several free IP-to-country layouts without preprocessing, so a CSV
 * from any of the bundled public sources (and most others) works directly:
 *   - IP2Location LITE DB1:  "from","to","CC","Country Name" (quoted decimal)
 *   - sapics/ip-location-db: from,to,CC                      (dotted, no name)
 *   - datasets/geoip2-ipv4:  CIDR,geoname,...,CC,Country,... (CIDR + columns)
 * Detection is by shape: a first field containing "/" is a CIDR block and the
 * country code is taken from whichever field is an exact 2-letter code;
 * otherwise the first two fields are the range start/end and the third is CC.
 *
 * Returns 1 when the line is a usable range for country_code (filling start,
 * end and name_out), 0 when the line should be skipped (header, other country,
 * malformed).
 */
static int parse_country_line(const char *line, const char *country_code,
                              uint32_t *start_out, uint32_t *end_out,
                              char *name_buf, size_t name_buf_size) {
  char fields[8][128];
  size_t n = split_csv(line, fields, 8);
  if (n < 2) {
    return 0;
  }

  /* CIDR form (datasets/geoip2 and similar): first field is a network block,
   * the country code sits in some later 2-letter column, and an adjacent
   * longer field may hold the country name. */
  if (strchr(fields[0], '/') != NULL) {
    /* Match the requested code against any 2-letter column. Matching the
     * target directly avoids mistaking a continent code (OC, NA, ...) in an
     * earlier column for the country code. */
    size_t cc_idx = n; /* sentinel: not found */
    for (size_t i = 1; i < n; i++) {
      if (is_country_code_token(fields[i]) &&
          strcmp(fields[i], country_code) == 0) {
        cc_idx = i;
        break;
      }
    }
    if (cc_idx == n) {
      return 0;
    }
    if (parse_ipv4_cidr(fields[0], start_out, end_out) != 0) {
      return 0;
    }
    /* Prefer a following non-code field as the display name. */
    if (cc_idx + 1 < n && !is_country_code_token(fields[cc_idx + 1]) &&
        fields[cc_idx + 1][0] != '\0') {
      snprintf(name_buf, name_buf_size, "%s", fields[cc_idx + 1]);
    } else {
      snprintf(name_buf, name_buf_size, "%s", country_code);
    }
    return 1;
  }

  /* Range form: from,to,CC[,name] (quoted decimal or unquoted dotted). */
  if (n < 3 || strcmp(fields[2], country_code) != 0) {
    return 0;
  }
  if (parse_ipv4_value(fields[0], start_out) != 0 ||
      parse_ipv4_value(fields[1], end_out) != 0) {
    return 0;
  }
  if (*start_out > *end_out) {
    return 0;
  }
  if (n >= 4 && fields[3][0] != '\0') {
    snprintf(name_buf, name_buf_size, "%s", fields[3]);
  } else {
    snprintf(name_buf, name_buf_size, "%s", country_code);
  }
  return 1;
}


/* ---- test harness ---- */

static int failures = 0;

static void check_ip(const char *s, int want_ok, uint32_t want) {
  uint32_t got = 0;
  int ok = parse_ipv4_value(s, &got) == 0;
  if (ok != want_ok || (want_ok && got != want)) {
    printf("FAIL ip '%s': ok=%d got=%u (want ok=%d val=%u)\n", s, ok, got,
           want_ok, want);
    failures++;
  }
}

static void check_cidr(const char *s, int want_ok, uint32_t ws, uint32_t we) {
  uint32_t a = 0, b = 0;
  int ok = parse_ipv4_cidr(s, &a, &b) == 0;
  if (ok != want_ok || (want_ok && (a != ws || b != we))) {
    printf("FAIL cidr '%s': ok=%d a=%u b=%u (want ok=%d %u-%u)\n", s, ok, a, b,
           want_ok, ws, we);
    failures++;
  }
}

static void check_line(const char *line, const char *cc, int want_ret,
                       uint32_t ws, uint32_t we, const char *wname) {
  uint32_t s = 0, e = 0;
  char name[128] = "";
  int ret = parse_country_line(line, cc, &s, &e, name, sizeof(name));
  int bad = ret != want_ret;
  if (ret == 1 && want_ret == 1 &&
      (s != ws || e != we || (wname && strcmp(name, wname) != 0))) {
    bad = 1;
  }
  if (bad) {
    printf("FAIL line '%s' cc=%s ret=%d s=%u e=%u name='%s'\n", line, cc, ret, s,
           e, name);
    failures++;
  }
}


/*
 * A single ASN selector: either an autonomous system number (e.g. 13335) or a
 * case-insensitive substring to match against the organisation name (e.g.
 * "cloudflare"). A filter is a list of these; a range matches if any selector
 * matches.
 */
typedef struct {
  int is_number;       /* 1 = match by ASN number, 0 = match by org substring */
  uint32_t number;     /* valid when is_number */
  char org[128];       /* lowercased org substring when !is_number */
} asn_selector_t;

typedef struct {
  asn_selector_t *items;
  size_t count;
} asn_filter_t;

static void str_tolower_copy(char *dst, size_t dst_size, const char *src) {
  size_t i = 0;
  for (; src[i] != '\0' && i + 1 < dst_size; i++) {
    unsigned char c = (unsigned char)src[i];
    dst[i] = (char)((c >= 'A' && c <= 'Z') ? c + 32 : c);
  }
  dst[i] = '\0';
}

/*
 * Parses a comma-separated ASN spec into a filter. Each item is either a
 * number, an "AS<number>" token, or an "org:<text>" / plain-text organisation
 * substring. A bare numeric item is treated as an ASN number; anything else is
 * an org-name substring (the optional "org:" prefix makes intent explicit).
 *
 * Returns 0 on success (filling *out), -1 on allocation failure or empty spec.
 */
static int parse_asn_filter(const char *spec, asn_filter_t *out) {
  out->items = NULL;
  out->count = 0;
  if (!spec || *spec == '\0') {
    return -1;
  }
  char *copy = strdup(spec);
  if (!copy) {
    return -1;
  }
  size_t capacity = 0;
  char *token = strtok(copy, ",");
  while (token) {
    /* Trim leading/trailing spaces. */
    while (*token == ' ') token++;
    size_t tlen = strlen(token);
    while (tlen > 0 && token[tlen - 1] == ' ') token[--tlen] = '\0';
    if (tlen == 0) {
      token = strtok(NULL, ",");
      continue;
    }

    if (out->count == capacity) {
      size_t newcap = capacity == 0 ? 8 : capacity * 2;
      asn_selector_t *ni = realloc(out->items, newcap * sizeof(*ni));
      if (!ni) {
        free(copy);
        free(out->items);
        out->items = NULL;
        out->count = 0;
        return -1;
      }
      out->items = ni;
      capacity = newcap;
    }
    asn_selector_t *sel = &out->items[out->count];

    const char *val = token;
    int force_org = 0;
    if (strncasecmp(token, "org:", 4) == 0) {
      val = token + 4;
      force_org = 1;
    } else if ((token[0] == 'A' || token[0] == 'a') &&
               (token[1] == 'S' || token[1] == 's') &&
               token[2] >= '0' && token[2] <= '9') {
      val = token + 2; /* "AS13335" -> "13335" */
    }

    char *endptr = NULL;
    errno = 0;
    unsigned long long num = strtoull(val, &endptr, 10);
    if (!force_org && *val != '\0' && endptr && *endptr == '\0' &&
        errno == 0 && num <= UINT32_MAX) {
      sel->is_number = 1;
      sel->number = (uint32_t)num;
      sel->org[0] = '\0';
    } else {
      sel->is_number = 0;
      sel->number = 0;
      str_tolower_copy(sel->org, sizeof(sel->org), val);
    }
    out->count++;
    token = strtok(NULL, ",");
  }
  free(copy);
  if (out->count == 0) {
    free(out->items);
    out->items = NULL;
    return -1;
  }
  return 0;
}

static void free_asn_filter(asn_filter_t *f) {
  if (f) {
    free(f->items);
    f->items = NULL;
    f->count = 0;
  }
}

/* Does an ASN number / org name match any selector in the filter? */
static int asn_filter_matches(const asn_filter_t *f, uint32_t asn,
                              const char *org) {
  char org_lower[128];
  str_tolower_copy(org_lower, sizeof(org_lower), org ? org : "");
  for (size_t i = 0; i < f->count; i++) {
    const asn_selector_t *s = &f->items[i];
    if (s->is_number) {
      if (s->number == asn) {
        return 1;
      }
    } else if (s->org[0] != '\0' && strstr(org_lower, s->org) != NULL) {
      return 1;
    }
  }
  return 0;
}

/*
 * Parses one line of an ASN database (from,to,ASN,"Org"; dotted or decimal
 * IPs) and reports whether it matches the filter. On a match, fills the range
 * and copies the organisation name into org_buf.
 *
 * Returns 1 on a matching range, 0 to skip (header, non-match, malformed).
 */
static int parse_asn_line(const char *line, const asn_filter_t *filter,
                          uint32_t *start_out, uint32_t *end_out,
                          char *org_buf, size_t org_buf_size) {
  char fields[6][128];
  size_t n = split_csv(line, fields, 6);
  if (n < 3) {
    return 0;
  }
  if (parse_ipv4_value(fields[0], start_out) != 0 ||
      parse_ipv4_value(fields[1], end_out) != 0) {
    return 0; /* header or non-numeric row */
  }
  if (*start_out > *end_out) {
    return 0;
  }
  char *endptr = NULL;
  errno = 0;
  unsigned long long asn = strtoull(fields[2], &endptr, 10);
  if (endptr == fields[2] || *endptr != '\0' || errno != 0 ||
      asn > UINT32_MAX) {
    return 0;
  }
  const char *org = (n >= 4) ? fields[3] : "";
  if (!asn_filter_matches(filter, (uint32_t)asn, org)) {
    return 0;
  }
  snprintf(org_buf, org_buf_size, "%s", org);
  return 1;
}

/* ---- ASN test helpers ---- */

static void check_asn_filter(const char *spec, int want_count) {
  asn_filter_t f;
  int r = parse_asn_filter(spec, &f);
  if (want_count < 0) {
    if (r == 0) { printf("FAIL asn-filter '%s' should have failed\n", spec); failures++; free_asn_filter(&f); }
    return;
  }
  if (r != 0) { printf("FAIL asn-filter '%s' parse\n", spec); failures++; return; }
  if ((int)f.count != want_count) { printf("FAIL asn-filter '%s' count=%zu want=%d\n", spec, f.count, want_count); failures++; }
  free_asn_filter(&f);
}

static void check_asn_line(const char *line, const char *spec, int want_ret, uint32_t ws, uint32_t we) {
  asn_filter_t f;
  if (parse_asn_filter(spec, &f) != 0) { printf("FAIL asn-line filter '%s'\n", spec); failures++; return; }
  uint32_t s = 0, e = 0; char org[128] = "";
  int ret = parse_asn_line(line, &f, &s, &e, org, sizeof(org));
  if (ret != want_ret || (want_ret == 1 && (s != ws || e != we))) {
    printf("FAIL asn-line '%s' spec='%s' ret=%d s=%u e=%u\n", line, spec, ret, s, e); failures++;
  }
  free_asn_filter(&f);
}

int main(void) {
  /* IPv4 scalar: decimal and dotted */
  check_ip("16777216", 1, 16777216u);
  check_ip("1.0.0.0", 1, 16777216u);
  check_ip("255.255.255.255", 1, 4294967295u);
  check_ip("", 0, 0);
  check_ip("1.2.3", 0, 0);
  check_ip("4294967296", 0, 0);
  check_ip("1.0.0.0x", 0, 0);

  /* CIDR expansion */
  check_cidr("1.0.0.0/24", 1, 16777216u, 16777471u);
  check_cidr("8.8.8.8/32", 1, 134744072u, 134744072u);
  check_cidr("0.0.0.0/0", 1, 0u, 4294967295u);
  check_cidr("10.0.0.0", 1, 167772160u, 167772160u);
  check_cidr("1.0.0.0/33", 0, 0, 0);
  check_cidr("1.0.0.0/-1", 0, 0, 0);

  /* IP2Location quoted form */
  check_line("\"16777216\",\"16777471\",\"US\",\"United States\"\n", "US", 1,
             16777216u, 16777471u, "United States");
  /* sapics dotted form, name defaults to CC */
  check_line("1.0.4.0,1.0.7.255,AU\n", "AU", 1, 16778240u, 16779263u, "AU");
  /* wrong country skipped */
  check_line("1.0.4.0,1.0.7.255,AU\n", "US", 0, 0, 0, NULL);
  /* CRLF endings */
  check_line("85.94.160.0,85.94.191.255,AD\r\n", "AD", 1, 1432264704u,
             1432272895u, "AD");
  /* reversed range rejected */
  check_line("1.0.7.255,1.0.4.0,AU\n", "AU", 0, 0, 0, NULL);
  /* header skipped */
  check_line("ip_from,ip_to,country_code\n", "AU", 0, 0, 0, NULL);
  /* geoip2 CIDR form: country code sits past a 2-letter continent code */
  check_line("1.0.0.0/24,2077456,OC,Oceania,AU,Australia,0,0\n", "AU", 1,
             16777216u, 16777471u, "Australia");
  check_line("1.0.1.0/24,1814991,AS,Asia,CN,China,0,0\n", "AU", 0, 0, 0, NULL);
  check_line("8.8.8.8/32,0,NA,North America,US,United States,0,0\n", "US", 1,
             134744072u, 134744072u, "United States");
  /* geoip2 text header skipped (no 2-letter token equals the target CC) */
  check_line("network,geoname_id,continent_code,continent_name,"
             "country_iso_code,country_name,x,y\n",
             "AU", 0, 0, 0, NULL);

  /* ASN filter parsing */
  check_asn_filter("13335", 1);
  check_asn_filter("13335,15169", 2);
  check_asn_filter("AS13335", 1);
  check_asn_filter("org:cloudflare", 1);
  check_asn_filter("cloudflare", 1);
  check_asn_filter("13335, org:google , AS15169", 3);
  check_asn_filter("", -1);

  /* ASN line matching: by number */
  check_asn_line("1.0.0.0,1.0.0.255,13335,\"Cloudflare, Inc.\"\n", "13335", 1,
                 16777216u, 16777471u);
  /* by org substring, case-insensitive */
  check_asn_line("1.0.0.0,1.0.0.255,13335,\"Cloudflare, Inc.\"\n", "org:cloud",
                 1, 16777216u, 16777471u);
  check_asn_line("1.0.0.0,1.0.0.255,13335,\"Cloudflare, Inc.\"\n", "CLOUDFLARE",
                 1, 16777216u, 16777471u);
  /* non-match by number and by org */
  check_asn_line("1.0.4.0,1.0.7.255,38803,Gtelecom Pty Ltd\n", "13335", 0, 0, 0);
  check_asn_line("1.0.4.0,1.0.7.255,38803,Gtelecom Pty Ltd\n", "org:cloudflare",
                 0, 0, 0);
  /* AS-prefixed spec matches a plain number in the db */
  check_asn_line("1.0.0.0,1.0.0.255,13335,X\n", "AS13335", 1, 16777216u,
                 16777471u);
  /* header row skipped */
  check_asn_line("network,start,asn,org\n", "13335", 0, 0, 0);

  if (failures) {
    printf("%d parser test(s) FAILED\n", failures);
    return 1;
  }
  printf("All CSV parser tests passed.\n");
  return 0;
}
