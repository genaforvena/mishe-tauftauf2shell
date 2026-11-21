// Loopback-only consumer for the stream overload of CVE-2026-103501.
// Calls hll_sketch::deserialize(std::istream&) from pinned 5.2.0; the copy at
// CouponList-internal.hpp:162 is source-bound (istream::read), unlike the
// byte-buffer memcpy at :116. No library source is copied or patched.
#include "hll.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <sstream>
#include <string>
#include <vector>

using namespace datasketches;

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
  const int port = argc > 1 ? std::atoi(argv[1]) : 38127;
  const int ls = ::socket(AF_INET, SOCK_STREAM, 0);
  if (ls < 0) { std::perror("socket"); return 2; }
  int one = 1;
  ::setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr;
  std::memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::bind(ls, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) { std::perror("bind"); return 2; }
  if (::listen(ls, 1) < 0) { std::perror("listen"); return 2; }
  std::printf("SERVICE_LISTEN port=%d pid=%d\n", port, static_cast<int>(::getpid()));
  std::fflush(stdout);

  const int cs = ::accept(ls, nullptr, nullptr);
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

  std::istringstream is(std::string(reinterpret_cast<const char*>(buf.data()), buf.size()));
  try {
    const auto sk = hll_sketch::deserialize(is);
    std::printf("SERVICE_DESERIALIZE rv=ok estimate=%f\n", sk.get_estimate());
  } catch (const std::exception& e) {
    std::printf("SERVICE_DESERIALIZE rv=exception what=%s\n", e.what());
  }
  std::fflush(stdout);
  ::close(cs);
  ::close(ls);
  std::printf("SERVICE_EXIT\n");
  std::fflush(stdout);
  return 0;
}
