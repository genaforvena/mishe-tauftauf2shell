// thorvg2shell loopback-only HTTP wire lane.
// Binds 127.0.0.1 exclusively. POST /decode with Content-Type image/jpeg sends
// the request body straight into tvg::Picture::load(data,size,"jpg") on the
// real pinned ThorVG library. No filesystem path is used for the decoded data.
// GET /health is a no-decode control endpoint.
#include <thorvg.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

static void respond(int fd, const char* body)
{
    char header[256];
    int n = std::snprintf(header, sizeof header,
                          "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                          "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                          std::strlen(body), body);
    if (write(fd, header, static_cast<size_t>(n)) < 0) { /* peer gone */ }
}

int main(int argc, char** argv)
{
    const char* portstr = argc > 1 ? argv[1] : "18081";
    int port = std::atoi(portstr);

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) { std::perror("socket"); return 2; }
    int one = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // loopback only
    if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0) {
        std::perror("bind"); return 2;
    }
    if (listen(listener, 4) < 0) { std::perror("listen"); return 2; }
    std::fprintf(stderr, "loopback_server: listening on 127.0.0.1:%d\n", port);
    std::fflush(stderr);

    for (;;) {
        int fd = accept(listener, nullptr, nullptr);
        if (fd < 0) { std::perror("accept"); return 2; }

        std::string req;
        char chunk[8192];
        size_t header_end = std::string::npos;
        size_t content_length = 0;
        while (header_end == std::string::npos) {
            ssize_t got = recv(fd, chunk, sizeof chunk, 0);
            if (got <= 0) break;
            req.append(chunk, static_cast<size_t>(got));
            header_end = req.find("\r\n\r\n");
            if (req.size() > 1024 * 1024) break;
        }
        if (header_end == std::string::npos) { close(fd); continue; }

        std::string headers = req.substr(0, header_end);
        std::string body = req.substr(header_end + 4);
        auto cl = headers.find("Content-Length:");
        if (cl != std::string::npos) {
            content_length = std::strtoul(headers.c_str() + cl + 15, nullptr, 10);
        }
        bool is_post = headers.rfind("POST ", 0) == 0;

        if (!is_post || headers.find("/health") != std::string::npos) {
            std::fprintf(stderr, "loopback_server: health\n");
            respond(fd, "HEALTH OK\n");
            std::fflush(stderr);
            close(fd);
            continue;
        }

        while (body.size() < content_length) {
            ssize_t got = recv(fd, chunk, sizeof chunk, 0);
            if (got <= 0) break;
            body.append(chunk, static_cast<size_t>(got));
        }
        std::fprintf(stderr, "loopback_server: decode request bytes=%zu\n", body.size());
        std::fflush(stderr);

        if (tvg::Initializer::init(0) != tvg::Result::Success) {
            respond(fd, "INIT FAIL\n"); close(fd); continue;
        }
        auto picture = tvg::Picture::gen();
        auto result = picture->load(body.data(), static_cast<uint32_t>(body.size()), "jpg", nullptr, true);
        float w = 0, h = 0;
        picture->size(&w, &h);
        char msg[128];
        std::snprintf(msg, sizeof msg, "DECODED result=%d size=%.0fx%.0f\n",
                      static_cast<int>(result), w, h);
        respond(fd, msg);
        std::fflush(stderr);
        tvg::Initializer::term();
        close(fd);
    }
}
