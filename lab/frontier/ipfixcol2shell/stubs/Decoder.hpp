#pragma once
#include "DecodeBuffer.hpp"

namespace tcp_in {
class Decoder {
public:
    virtual ~Decoder() = default;
    virtual DecodeBuffer &decode() = 0;
    virtual const char *get_name() const = 0;
};
} // namespace tcp_in
