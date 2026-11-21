// Real-upstream DataSketches HLL CouponList deserialization driver.
// No library code is copied or modified: hll.hpp and its pinned headers come
// from the 5.2.0 / 5.3.0 release tarballs extracted by run.sh. The only
// stand-in is the allocator used in readback/guard modes, which places the
// 8-entry coupon vector in a page-aligned region so chosen bytes can be
// observed (readback) or the first past-end store can fault (guard).
#include "hll.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include <vector>

#include <sys/mman.h>

using namespace datasketches;

static void* g_pages[8] = {};
static void* g_ptrs[8] = {};
static int g_npages = 0;
static uint8_t* g_last = nullptr;
static bool g_guard = false;

template <class T>
struct PageAlloc {
  using value_type = T;
  PageAlloc() = default;
  template <class U> PageAlloc(const PageAlloc<U>&) noexcept {}

  T* allocate(std::size_t n) {
    if (sizeof(T) == sizeof(uint32_t) && n == 8) {
      void* base = mmap(nullptr, 8192, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (base == MAP_FAILED) throw std::bad_alloc();
      void* ret = g_guard ? static_cast<void*>(static_cast<uint8_t*>(base) + 4096 - 32) : base;
      if (g_guard && mprotect(static_cast<uint8_t*>(base) + 4096, 4096, PROT_NONE) != 0) {
        throw std::bad_alloc();
      }
      if (g_npages < 8) {
        g_pages[g_npages] = base;
        g_ptrs[g_npages] = ret;
        ++g_npages;
      }
      g_last = static_cast<uint8_t*>(ret);
      return static_cast<T*>(ret);
    }
    return std::allocator<T>().allocate(n);
  }

  void deallocate(T* p, std::size_t n) noexcept {
    for (int i = 0; i < g_npages; ++i) {
      if (g_pages[i] != nullptr && g_ptrs[i] == static_cast<void*>(p)) {
        munmap(g_pages[i], 8192);
        g_pages[i] = nullptr;
        g_ptrs[i] = nullptr;
        return;
      }
    }
    std::allocator<T>().deallocate(p, n);
  }

  template <class U> bool operator==(const PageAlloc<U>&) const noexcept { return true; }
  template <class U> bool operator!=(const PageAlloc<U>&) const noexcept { return false; }
};

using PageSketch = hll_sketch_alloc<PageAlloc<uint8_t>>;

static std::vector<uint8_t> make_hostile(uint8_t count, uint8_t value) {
  hll_sketch seed(8);
  seed.update(1);
  seed.update(2);
  const auto valid = seed.serialize_compact();
  // LIST wire format: count byte at 6, coupons begin at byte 8. Every payload
  // byte is the caller-chosen value; the first 16 bytes carry a real header
  // and two real coupons so only the declared count is malformed.
  const size_t need = 8 + static_cast<size_t>(count) * 4;
  std::vector<uint8_t> buf(need, value);
  std::memcpy(buf.data(), valid.data(), std::min(valid.size(), buf.size()));
  buf[6] = count;
  return buf;
}

int main(int argc, char** argv) {
  const std::string mode = argc > 1 ? argv[1] : "asan";
  const uint8_t count = static_cast<uint8_t>(argc > 2 ? std::atoi(argv[2]) : 64);
  const uint8_t value = static_cast<uint8_t>(argc > 3 ? std::atoi(argv[3]) : 0x5a);
  const auto buf = make_hostile(count, value);

  if (mode == "asan" || mode == "fixed") {
    try {
      const auto sk = hll_sketch::deserialize(buf.data(), buf.size());
      std::printf("%s count=%u rv=ok estimate=%f\n", mode.c_str(), count, sk.get_estimate());
    } catch (const std::exception& e) {
      std::printf("%s count=%u rv=exception what=%s\n", mode.c_str(), count, e.what());
    }
    return 0;
  }

  g_guard = (mode == "guard");
  try {
    const auto sk = PageSketch::deserialize(buf.data(), buf.size(), PageAlloc<uint8_t>());
    std::printf("%s count=%u value=%02x rv=ok", mode.c_str(), count, value);
    if (mode == "readback") {
      for (const int off : {32, 48, 64, 96, 128, 224, 255}) {
        std::printf(" +%d=%02x", off, g_last[off]);
      }
    }
    std::printf(" estimate=%f\n", sk.get_estimate());
  } catch (const std::exception& e) {
    std::printf("%s count=%u value=%02x rv=exception what=%s\n", mode.c_str(), count, value,
                e.what());
  }
  return 0;
}
