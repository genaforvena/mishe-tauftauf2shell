// Extracted, source-bound harness for CVE-2026-135746.
// The vulnerable loop below is copied VERBATIM from pinned upstream
// Samsung/lwnode b3de7be5 src/api-data.cc:2194-2203 (UTF-16 storage path of
// String::WriteOneByte). run.sh checks the exact pinned byte hash on every
// run. The fixed loop is the upstream PR #188 replacement. No lwnode build,
// no JS engine, no process outside this harness is involved.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>

struct ByteData {
    const uint8_t * buffer;
    size_t length;
};

// Pinned bytes 2194-2203, verbatim (oneByteBufferData -> one).
static int vuln_write(uint8_t * buffer, int start, int length, const ByteData & one) {
  int bufferCapacity = length;
  int nchars = 0;
  {
    size_t j = 0;
    for (size_t i = start * 2; i < one.length; i += 2) {
      if (j > static_cast<size_t>(bufferCapacity)) {
        break;
      }

      buffer[j] = ((uint8_t*)(one.buffer))[i];
      j++;
    }
    nchars = j;
  }
  return nchars;
}

// Upstream fix 442b6eb (PR #188): bound by min(capacity, length - start).
static int fixed_write(uint8_t * buffer, int start, int length, const ByteData & one) {
  int bufferCapacity = length;
  if (start < 0 || static_cast<size_t>(start) > one.length) return 0;
  int nchars = std::min(static_cast<size_t>(bufferCapacity), one.length - start);
  for (int i = 0; i < nchars; i++) {
    buffer[i] = one.buffer[start + i];
  }
  return nchars;
}

int main(int argc, char ** argv) {
    const bool fixed = argc > 1 && strcmp(argv[1], "fixed") == 0;
    const bool attack = argc > 2 && strcmp(argv[2], "attack") == 0;
    const uint8_t fill = argc > 3 ? (uint8_t)strtoul(argv[3], nullptr, 16) : 0x41;
    const int capacity = 8;
#ifdef __SANITIZE_ADDRESS__
    const size_t alloc = (size_t)capacity; // exact size so ASan sees the overrun
#else
    const size_t alloc = (size_t)capacity + 8; // canary readback in plain build
#endif
    uint8_t * out = (uint8_t *)malloc(alloc);
    memset(out, 0xcc, alloc);
    // What the UTF-16-backed string contributes: low bytes of code units.
    uint8_t source[40];
    for (unsigned i = 0; i < sizeof(source); ++i) source[i] = fill;
    ByteData one = { source, attack ? sizeof(source) : (size_t)(capacity * 2) };
    int n = fixed ? fixed_write(out, 0, capacity, one)
                  : vuln_write(out, 0, capacity, one);
#ifndef __SANITIZE_ADDRESS__
    printf("%s %s n=%d byte8=0x%02x canary=0x%02x\n",
           fixed ? "fixed" : "vuln", attack ? "attack" : "safe",
           n, out[8], out[16 - 1]);
#else
    printf("%s %s n=%d\n", fixed ? "fixed" : "vuln",
           attack ? "attack" : "safe", n);
#endif
    free(out);
    return 0;
}
