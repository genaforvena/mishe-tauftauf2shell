/* Loopback TCP driver for the plugin's real Lz4Decoder/DecodeBuffer/ByteVector
 * sources. No external network: binds 127.0.0.1:0 and connects to itself.
 * Optional TRACK_ALLOC passivately records 24-byte operator new calls; it does
 * not replace the allocator (malloc/ASan still perform every allocation).
 */
#include "Lz4Decoder.hpp"
#include "ByteVector.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <iostream>
#include <iterator>
#include <new>
#include <thread>
#include <vector>

#ifdef TRACK_ALLOC
static void *g_candidates[128];
static int g_candidate_count = 0;
void *operator new(std::size_t n) {
    void *p = std::malloc(n ? n : 1);
    if (!p) throw std::bad_alloc();
    if (n == 24 && g_candidate_count < 128) {
        g_candidates[g_candidate_count++] = p;
    }
    return p;
}
void operator delete(void *p) noexcept { std::free(p); }
void operator delete(void *p, std::size_t) noexcept { std::free(p); }
#endif

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "usage: driver WIRE_FILE\n";
        return 2;
    }
    std::ifstream in(argv[1], std::ios::binary);
    std::vector<uint8_t> wire((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
    if (wire.empty()) {
        std::cerr << "empty wire file\n";
        return 2;
    }
    std::cout << "wire_bytes=" << wire.size() << std::endl;

    int lfd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) return 2;
    int one = 1;
    ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    int rcvbuf = 1 << 20;
    ::setsockopt(lfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(lfd, reinterpret_cast<struct sockaddr *>(&addr), sizeof addr) != 0) return 2;
    if (::listen(lfd, 1) != 0) return 2;
    socklen_t alen = sizeof addr;
    if (::getsockname(lfd, reinterpret_cast<struct sockaddr *>(&addr), &alen) != 0) return 2;
    std::cout << "bind=127.0.0.1:" << ntohs(addr.sin_port) << std::endl;

    std::thread client([&]() {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return;
        struct sockaddr_in srv {};
        srv.sin_family = AF_INET;
        srv.sin_port = addr.sin_port;
        srv.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::connect(fd, reinterpret_cast<struct sockaddr *>(&srv), sizeof srv) != 0) {
            ::close(fd);
            return;
        }
        size_t sent = 0;
        while (sent < wire.size()) {
            ssize_t n = ::send(fd, wire.data() + sent, wire.size() - sent, 0);
            if (n <= 0) break;
            sent += static_cast<size_t>(n);
        }
        ::shutdown(fd, SHUT_WR);
        ::close(fd);
    });

    int cfd = ::accept(lfd, nullptr, nullptr);
    ::close(lfd);
    if (cfd < 0) {
        client.join();
        return 2;
    }
    std::cout << "accepted_loopback=1" << std::endl;

    try {
        tcp_in::Lz4Decoder dec(cfd);
        tcp_in::DecodeBuffer &buf = dec.decode();
        size_t messages = 0;
        size_t decoded = 0;
        unsigned first = 0;
        buf.process_decoded([&](tcp_in::ByteVector &&v) {
            messages++;
            decoded += v.size();
            if (v.size() && messages == 1) first = v.data()[0];
        });
        std::cout << "decode_ok=1 messages=" << messages
                  << " decoded_bytes=" << decoded
                  << " first_byte=" << first << std::endl;
    } catch (const std::exception &e) {
        std::cout << "decode_ok=0 exception=" << e.what() << std::endl;
    }

#ifdef TRACK_ALLOC
    for (int i = 0; i < g_candidate_count; i++) {
        const unsigned char *p = static_cast<const unsigned char *>(g_candidates[i]);
        std::cout << "alloc24[" << i << "]=" << static_cast<const void *>(p)
                  << " off0=" << static_cast<unsigned>(p[0])
                  << " off24=" << static_cast<unsigned>(p[24])
                  << " off28=" << static_cast<unsigned>(p[28])
                  << " off64999=" << static_cast<unsigned>(p[64999]) << std::endl;
    }
    std::cout << "alloc24_count=" << g_candidate_count << std::endl;
#endif

    ::close(cfd);
    client.join();
    return 0;
}
