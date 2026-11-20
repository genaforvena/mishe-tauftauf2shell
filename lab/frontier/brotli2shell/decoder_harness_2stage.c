/* Two-stage standalone decoder harness for CVE-2026-111497.
 * Reuses ONE BrotliDecoderState across stage 1 and stage 2, mirroring the
 * public PoC's framed protocol where stage 1 primes the internal buffer and
 * stage 2 supplies the overflowing bytes. Loopback/file only, no network.
 * Usage: decoder_harness_2stage <stage1> <stage2> [max-calls-per-stage] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "brotli/decode.h"

static uint8_t *read_file(const char *path, size_t *sz) {
  FILE *f = fopen(path, "rb");
  if (!f) { perror(path); return NULL; }
  if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); fclose(f); return NULL; }
  long n = ftell(f);
  if (n <= 0) { fclose(f); return NULL; }
  rewind(f);
  uint8_t *buf = (uint8_t *)malloc((size_t)n);
  if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
  fclose(f);
  *sz = (size_t)n;
  return buf;
}

static void feed(BrotliDecoderState *s, const char *label,
                 uint8_t *in, size_t sz, long max_calls) {
  uint8_t out[65536];
  const uint8_t *next_in = in;
  size_t avail_in = sz;
  uint8_t *next_out = out;
  size_t avail_out = sizeof(out);
  size_t total_out = 0;
  long calls = 0;
  BrotliDecoderResult r = BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT;
  clock_t t0 = clock();
  while (calls < max_calls) {
    r = BrotliDecoderDecompressStream(s, &avail_in, &next_in,
                                       &avail_out, &next_out, &total_out);
    calls++;
    if (r == BROTLI_DECODER_RESULT_SUCCESS || r == BROTLI_DECODER_RESULT_ERROR) break;
    if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
      next_out = out;
      avail_out = sizeof(out);
    }
  }
  printf("%s: result=%d error_code=%d calls=%ld total_out=%zu avail_in=%zu secs=%.3f\n",
         label, (int)r, (int)BrotliDecoderGetErrorCode(s), calls, total_out,
         avail_in, (double)(clock() - t0) / CLOCKS_PER_SEC);
  fflush(stdout);
}

int main(int argc, char **argv) {
  if (argc < 3) { fprintf(stderr, "usage: %s <stage1> <stage2> [max-calls]\n", argv[0]); return 2; }
  size_t n1 = 0, n2 = 0;
  uint8_t *s1 = read_file(argv[1], &n1);
  uint8_t *s2 = read_file(argv[2], &n2);
  if (!s1 || !s2) { fprintf(stderr, "read failed\n"); return 2; }
  long max_calls = (argc > 3) ? strtol(argv[3], NULL, 10) : 1000000;
  BrotliDecoderState *s = BrotliDecoderCreateInstance(NULL, NULL, NULL);
  if (!s) return 2;
  printf("stage1_size=%zu stage2_size=%zu\n", n1, n2);
  feed(s, "stage1", s1, n1, max_calls);
  feed(s, "stage2", s2, n2, max_calls);
  BrotliDecoderDestroyInstance(s);
  free(s1); free(s2);
  return 0;
}
