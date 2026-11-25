// libraw2shell W17: minimal loopback consumer. Receives raw file bytes on a
// single TCP connection bound to 127.0.0.1, decodes them in-process with the
// unmodified pinned LibRaw 0.22.3 and the -n 1 option (threshold=1.0), then
// exits. Passing "safe" as the second argument omits the option (no-option
// control). No debugger, no forced call, no external network.
#include <libraw/libraw.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <vector>

int main(int argc, char **argv)
{
    if (argc != 2 && argc != 3) {
        std::fprintf(stderr, "usage: %s PORT [safe]\n", argv[0]); return 2;
    }
    int port = std::atoi(argv[1]);
    bool shrink_option = (argc == 2);

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { std::perror("socket"); return 2; }
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<unsigned short>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof addr) < 0) {
        std::perror("bind"); return 2;
    }
    if (::listen(fd, 1) < 0) { std::perror("listen"); return 2; }
    int conn = ::accept(fd, nullptr, nullptr);
    if (conn < 0) { std::perror("accept"); return 2; }
    std::vector<unsigned char> buf;
    unsigned char chunk[65536];
    for (;;) {
        ssize_t n = ::read(conn, chunk, sizeof chunk);
        if (n < 0) { std::perror("read"); return 2; }
        if (n == 0) break;
        buf.insert(buf.end(), chunk, chunk + n);
    }
    ::close(conn);
    ::close(fd);
    std::fprintf(stderr, "RECV bytes=%zu option=%d\n", buf.size(), shrink_option ? 1 : 0);

    LibRaw raw;
    if (shrink_option) raw.imgdata.params.threshold = 1.0f; // dcraw_emu -n 1
    int rc = raw.open_buffer(buf.data(), buf.size());
    std::fprintf(stderr, "OPEN rc=%d\n", rc);
    if (rc != LIBRAW_SUCCESS) return 3;
    rc = raw.unpack();
    std::fprintf(stderr, "UNPACK rc=%d w=%d h=%d\n", rc,
                 raw.imgdata.sizes.width, raw.imgdata.sizes.height);
    if (rc != LIBRAW_SUCCESS) return 4;
    rc = raw.dcraw_process();
    std::fprintf(stderr, "PROCESS rc=%d\n", rc);
    return 0;
}
