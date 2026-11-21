#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <vector>
#include "DecodeBuffer.hpp"

/* Upstream Lz4Decoder.cpp:180 calls ::read_until_n explicitly. */
inline bool read_until_n(size_t n, int fd, std::vector<uint8_t> &v,
                         tcp_in::DecodeBuffer &) {
    while (v.size() < n) {
        uint8_t tmp[4096];
        const size_t want = std::min(sizeof tmp, n - v.size());
        ssize_t r = ::read(fd, tmp, want);
        if (r <= 0) {
            return false;
        }
        v.insert(v.end(), tmp, tmp + r);
    }
    return true;
}
