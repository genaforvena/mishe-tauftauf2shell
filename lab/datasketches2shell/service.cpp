// Loopback-only consumer for CVE-2026-103501.
// Reads a 4-byte big-endian length prefix and one HLL sketch image from a
// locally accepted TCP connection, then calls the public 5.2.0 API
// hll_sketch::deserialize(bytes, len). No library source is copied, patched or
// shimmed; this file is only the front end that supplies the untrusted image.
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


static bool read_exact(int fd, uint8_t* dst, size_t n) {
  size_t done = 0;
  while (done < n) {
    const ssize_t r = ::read(fd, dst + done, n - done);
    if (r == 0) return false;
    if (r < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    done += static_cast<size_t>(r);
  }
  return true;
}

int main(int argc, char** argv) {
  const int port = argc > 1 ? std::atoi(argv[1]) : 38117;
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
  if (argc > 2 && std::strcmp(argv[2], "postalloc") == 0) {
    std::vector<uint8_t> post(512, 0x11);
    std::printf("SERVICE_POSTALLOC ok byte=%02x\n", post[0]);
    std::fflush(stdout);
  }
  ::close(cs);
  ::close(ls);
  std::printf("SERVICE_EXIT\n");
  std::fflush(stdout);
  return 0;
}
