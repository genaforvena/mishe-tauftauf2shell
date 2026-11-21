/* Harness-owned stand-in for upstream DecodeBuffer: records the bytes the
 * pinned decoder hands to the decode buffer, and stops the decode loop as
 * soon as any output is available. No upstream logic is retyped here.
 */
#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace tcp_in {
class DecodeBuffer {
public:
    bool enough_data() const { return m_have > 0; }
    bool is_eof_reached() const { return false; }
    void read_from(const uint8_t *data, size_t size, size_t data_size, size_t position) {
        for (size_t i = 0; i < data_size; ++i) {
            m_out.push_back(data[(position + i) % size]);
        }
        m_have += data_size;
    }
    const std::vector<uint8_t> &out() const { return m_out; }

private:
    size_t m_have = 0;
    std::vector<uint8_t> m_out;
};
} // namespace tcp_in
