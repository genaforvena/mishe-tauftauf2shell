/* Differential driver for the pinned CESNET ipfixcol2 TCP/LZ4 decoder.
 * The upstream Lz4Decoder.cpp is compiled verbatim with #line-preserving
 * includes from pins/; only the surrounding I/O stubs are harness-owned.
 */
#include "Lz4Decoder.hpp"

#ifndef DECLARED_SIZE
#define DECLARED_SIZE 65000
#endif

#include <exception>
#include <string>
#include <vector>
#include <unistd.h>

#ifdef CHOSEN_COLLAB
#include <sys/mman.h>
static bool g_armed = false;
static void *g_arena = nullptr;
static void *g_arena_rec = nullptr;
static const size_t kArenaSize = 1u << 20;
static const size_t kRing = RING_SIZE;

void *operator new(std::size_t n) {
    if (g_armed && n == kRing && !g_arena) {
        g_arena = mmap(nullptr, kArenaSize, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (g_arena != MAP_FAILED) {
            g_arena_rec = g_arena;
            return g_arena;
        }
        g_arena = nullptr;
    }
    void *p = std::malloc(n ? n : 1);
    if (!p) throw std::bad_alloc();
    return p;
}
void operator delete(void *p) noexcept {
    if (p == g_arena_rec) return;
    std::free(p);
}
void operator delete(void *p, std::size_t) noexcept { ::operator delete(p); }
#endif

static std::vector<uint8_t> read_all() {
    std::vector<uint8_t> out;
    uint8_t buf[4096];
    ssize_t n;
    while ((n = ::read(0, buf, sizeof buf)) > 0) {
        out.insert(out.end(), buf, buf + n);
    }
    return out;
}

int main() {
    const auto wire = read_all();
    int fds[2];
    if (::pipe(fds) != 0) return 90;
    size_t off = 0;
    while (off < wire.size()) {
        ssize_t n = ::write(fds[1], wire.data() + off, wire.size() - off);
        if (n <= 0) return 91;
        off += static_cast<size_t>(n);
    }
    ::close(fds[1]);

    int rc = 0;
    try {
        tcp_in::Lz4Decoder dec(fds[0]);
#ifdef CHOSEN_COLLAB
        g_armed = true;
#endif
        auto &out = dec.decode();
#ifdef CHOSEN_COLLAB
        g_armed = false;
#endif
        std::printf("decode_ok=1 out_bytes=%zu\n", out.out().size());
        if (!out.out().empty()) {
            std::printf("out_first=");
            for (size_t i = 0; i < out.out().size() && i < 16; ++i) {
                std::printf("%02x", out.out()[i]);
            }
            std::printf("\n");
        }
#ifdef CHOSEN_COLLAB
        if (g_arena_rec) {
            const auto *a = static_cast<const uint8_t *>(g_arena_rec);
            const size_t offsets[] = {0, kRing, kRing + 4,
                                      DECLARED_SIZE - 1, DECLARED_SIZE,
                                      DECLARED_SIZE + 1};
            std::printf("arena_offsets=");
            for (size_t i = 0; i < sizeof offsets / sizeof offsets[0]; ++i) {
                std::printf("%zu:%02x ", offsets[i], a[offsets[i]]);
            }
            std::printf("\n");
            size_t run = 0;
            for (size_t i = kRing; i < DECLARED_SIZE; ++i) {
                if (a[i] == 0x5a) ++run;
            }
            std::printf("chosen_5a_past_end=%zu\n", run);
        } else {
            std::printf("arena_offsets=NONE\n");
        }
#endif
    } catch (const std::exception &e) {
#ifdef CHOSEN_COLLAB
        g_armed = false;
#endif
        std::printf("decode_ok=0 exception=%s\n", e.what());
        rc = 2;
    }
    ::close(fds[0]);
    std::fflush(stdout);
    return rc;
}
