/* Chunked-feed standalone decoder harness for CVE-2026-111497 screening.
 * Feeds the crafted stream in bounded chunks so that unconsumed bytes remain
 * in the bit reader when the forbidden block switch is reached — the layout
 * the advisory describes for the internal-buffer over-write.
 * Usage: decoder_harness_chunked <stream-file> [chunk-size] [max-calls] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "brotli/decode.h"

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: %s <stream-file> [chunk] [max-calls]\n", argv[0]); return 2; }
  FILE *f = fopen(argv[1], "rb");
  if (!f) { perror("fopen"); return 2; }
  if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); return 2; }
  long sz = ftell(f);
  if (sz <= 0) { fprintf(stderr, "bad size %ld\n", sz); return 2; }
  rewind(f);
  uint8_t *in = (uint8_t *)malloc((size_t)sz);
  if (!in || fread(in, 1, (size_t)sz, f) != (size_t)sz) { fprintf(stderr, "read failed\n"); return 2; }
  fclose(f);

  size_t chunk = (argc > 2) ? (size_t)strtoul(argv[2], NULL, 10) : 65536;
  long max_calls = (argc > 3) ? strtol(argv[3], NULL, 10) : 1000000;
  uint8_t out[65536];
  BrotliDecoderState *s = BrotliDecoderCreateInstance(NULL, NULL, NULL);
  if (!s) { fprintf(stderr, "create failed\n"); return 2; }

  size_t fed = 0;
  const uint8_t *next_in = in;
  size_t avail_in = 0;
  uint8_t *next_out = out;
  size_t avail_out = sizeof(out);
  size_t total_out = 0;
  long calls = 0;
  BrotliDecoderResult r = BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT;
  clock_t t0 = clock();
  while (calls < max_calls) {
    if (avail_in == 0 && fed < (size_t)sz) {
      size_t n = (size_t)sz - fed;
      if (n > chunk) n = chunk;
      next_in = in + fed;
      avail_in = n;
      fed += n;
    }
    r = BrotliDecoderDecompressStream(s, &avail_in, &next_in,
                                       &avail_out, &next_out, &total_out);
    calls++;
    if (r == BROTLI_DECODER_RESULT_SUCCESS || r == BROTLI_DECODER_RESULT_ERROR) break;
    if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
      next_out = out;
      avail_out = sizeof(out);
    }
  }
  double secs = (double)(clock() - t0) / CLOCKS_PER_SEC;
  printf("chunk=%zu result=%d error_code=%d calls=%ld total_out=%zu fed=%zu avail_in=%zu secs=%.3f\n",
         chunk, (int)r, (int)BrotliDecoderGetErrorCode(s), calls, total_out,
         fed, avail_in, secs);
  fflush(stdout);
  BrotliDecoderDestroyInstance(s);
  free(in);
  return 0;
}
