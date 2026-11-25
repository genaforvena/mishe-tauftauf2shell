// Verbatim lines 43-87 of pins/model-v4.8.0.cc (identical in pins/model-fixed.cc).
// Only the surrounding namespace and the stand-in `binary_file` are added.
#pragma once
#include <istream>
#include <string>
#include <stdexcept>
#include <cstddef>

namespace ctranslate2 {
    static inline void report_stream_error(const std::streampos position,
                                           const size_t read_size,
                                           const std::string& read_type) {
      throw std::runtime_error("File " + binary_file + " is incomplete: "
                               + "failed to read a " + read_type + " of size "
                               + std::to_string(read_size)
                               + " at position "
                               + std::to_string(position));
    }

    template <typename T>
    T consume(std::istream& in) {
      const std::streampos position = in.tellg();
      const size_t read_size = sizeof (T);
      T val;
      in.read(reinterpret_cast<char*>(&val), read_size);
      if (!in)
        report_stream_error(position, read_size, "value");
      return val;
    }

    template <typename T>
    T* consume(std::istream& in, size_t n, T* data = nullptr) {
      if (n == 0)
        return nullptr;
      const std::streampos position = in.tellg();
      const size_t read_size = n * sizeof (T);
      T* dst = data ? data : new T[n];
      in.read(reinterpret_cast<char*>(dst), read_size);
      if (!in) {
        if (dst != data)
          delete [] dst;
        report_stream_error(position, read_size, "buffer");
      }
      return dst;
    }

    template<>
    std::string consume(std::istream& in) {
      const auto str_length = consume<uint16_t>(in);
      const auto c_str = consume<char>(in, str_length);
      std::string str(c_str);
      delete [] c_str;
      return str;
    }
}
