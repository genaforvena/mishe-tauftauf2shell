// Frontier-authored driver: parses a real .cin header with verbatim
// upstream libcineon, then calls the pinned CineonInput::open() sink slice.
#include "common.h"

FakeReader m_cin;

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s file.cin\n", argv[0]);
        return 2;
    }
    cineon::InStream stream;
    if (!stream.Open(argv[1])) {
        std::fprintf(stderr, "open failed\n");
        return 1;
    }
    cineon::Reader cin;
    cin.SetInStream(&stream);
    if (!cin.ReadHeader()) {
        std::fprintf(stderr, "header read failed\n");
        return 1;
    }
    m_cin.header.n = cin.header.NumberOfElements();
    std::printf("NumberOfElements=%d\n", m_cin.header.n);
    bool ok = open_like();
    std::printf("open_like=%d\n", ok ? 1 : 0);
    return 0;
}
