// Emits a genuine pinned-5.2.0 compact LIST-mode sketch image for the client to
// mutate (only wire byte 6 and the chosen payload differ). Uses the library's
// own serializer verbatim.
#include "hll.hpp"

#include <cstdio>
#include <vector>

int main(int argc, char** argv) {
  if (argc < 2) return 2;
  datasketches::hll_sketch seed(8);
  seed.update(1);
  seed.update(2);
  const auto valid = seed.serialize_compact();
  std::FILE* f = std::fopen(argv[1], "wb");
  if (f == nullptr) return 2;
  const size_t n = std::fwrite(valid.data(), 1, valid.size(), f);
  std::fclose(f);
  std::printf("SEED bytes=%zu\n", n);
  return n == valid.size() ? 0 : 2;
}
