/* Loopback-only standalone decoder harness for CVE-2026-111497 screening.
 * Reads a crafted Brotli stream from a file and feeds it to
 * BrotliDecoderDecompressStream in one pass, then keeps calling with no more
 * input to observe NEEDS_MORE_INPUT / error behaviour. No network, no external
 * probe. Usage: decoder_harness <stream-file> [max-calls] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "brotli/decode.h"

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: %s <stream-file> [max-calls]\n", argv[0]); return 2; }
  FILE *f = fopen(argv[1], "rb");
  if (!f) { perror("fopen"); return 2; }
  if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); return 2; }
  long sz = ftell(f);
  if (sz <= 0) { fprintf(stderr, "bad size %ld\n", sz); return 2; }
  rewind(f);
  uint8_t *in = (uint8_t *)malloc((size_t)sz);
  if (!in || fread(in, 1, (size_t)sz, f) != (size_t)sz) { fprintf(stderr, "read failed\n"); return 2; }
  fclose(f);

  long max_calls = (argc > 2) ? strtol(argv[2], NULL, 10) : 1000000;
  uint8_t out[65536];
  BrotliDecoderState *s = BrotliDecoderCreateInstance(NULL, NULL, NULL);
  if (!s) { fprintf(stderr, "create failed\n"); return 2; }

  const uint8_t *next_in = in;
  size_t avail_in = (size_t)sz;
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
    /* NEEDS_MORE_INPUT with avail_in == 0: keep calling; the vulnerable
       decoder may spin or corrupt state here. External timeout caps the run. */
  }
  double secs = (double)(clock() - t0) / CLOCKS_PER_SEC;
  printf("result=%d error_code=%d calls=%ld total_out=%zu avail_in=%zu secs=%.3f\n",
         (int)r, (int)BrotliDecoderGetErrorCode(s), calls, total_out, avail_in, secs);
  fflush(stdout);
  BrotliDecoderDestroyInstance(s);
  free(in);
  return 0;
}
