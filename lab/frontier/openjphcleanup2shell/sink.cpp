// Frontier scaffolding: call the pinned generic HT cleanup decoder directly
// with an exactly-sized heap buffer. No upstream source is edited.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "ojph_block_decoder.h"

int main(int argc, char **argv)
{
  // argv: [rows] [missing_msbs] [byte0 byte1 ...]; rows=1 models the
  // vulnerable codeblock allocation, rows=2 the fixed allocation.
  unsigned rows = argc > 1 ? (unsigned)strtoul(argv[1], 0, 0) : 1;
  unsigned missing_msbs = argc > 2 ? (unsigned)strtoul(argv[2], 0, 0) : 1;
  unsigned char coded[32];
  size_t coded_len = 0;
  if (argc > 3) {
    for (int i = 3; i < argc && coded_len < sizeof(coded); ++i)
      coded[coded_len++] = (unsigned char)strtoul(argv[i], 0, 0);
  } else {
    coded[0] = 0x02; coded[1] = 0x00; coded_len = 2;
  }

  const uint32_t width = 8, height = 1, stride = 8;
  // Exact rows-row buffer: no allocator slack, no extra allocation.
  uint32_t *buf = (uint32_t *)malloc(rows * stride * sizeof(uint32_t));
  if (!buf) return 2;
  memset(buf, 0x5a, rows * stride * sizeof(uint32_t));

  bool ok = ojph::local::ojph_decode_codeblock32(
      coded, buf, missing_msbs, 1, (uint32_t)coded_len, 0,
      width, height, stride, false);

  uint32_t row0_or = 0, row1_or = 0;
  for (size_t i = 0; i < stride; ++i) row0_or |= buf[i];
  if (rows > 1) for (size_t i = 0; i < stride; ++i) row1_or |= buf[stride + i];
  printf("DECODE=%d ROWS=%u WIDTH=%u HEIGHT=%u STRIDE=%u ROW0_OR=%08x ROW1_OR=%08x\n",
         ok ? 1 : 0, rows, width, height, stride, row0_or, row1_or);
  free(buf);
  return 0;
}
