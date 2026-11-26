// Frontier-authored build shim. libcineon headers use three OIIO::Strutil
// helpers; this stand-in implements only those, with no OIIO library build.
#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace OIIO {

using string_view = std::string_view;

template <typename T>
static inline std::string any_to_string(const T& value) {
    if constexpr (std::is_convertible_v<T, std::string>) {
        return std::string(value);
    } else {
        std::ostringstream os;
        os << value;
        return os.str();
    }
}

namespace Strutil {

template <typename D, typename S>
inline void safe_strcpy(D* dst, const S& src, std::size_t n) {
    if (!dst || n == 0) return;
    std::string s = any_to_string(src);
    std::size_t k = std::min(n - 1, s.size());
    std::memcpy(dst, s.data(), k);
    dst[k] = '\0';
}

inline int stoi(string_view sv) {
    std::string s(sv);
    char* end = nullptr;
    long v = std::strtol(s.c_str(), &end, 10);
    return end == s.c_str() ? 0 : static_cast<int>(v);
}

namespace fmt {

template <typename... Args>
inline std::string format(const char* pattern, Args&&... args) {
    std::vector<std::string> values{any_to_string(args)...};
    std::string out;
    std::size_t next = 0;
    for (const char* p = pattern; *p;) {
        if (*p == '{' && *(p + 1) != '{') {
            while (*p && *p != '}') ++p;
            if (*p) ++p;
            if (next < values.size()) out += values[next++];
        } else {
            out += *p++;
        }
    }
    return out;
}

}  // namespace fmt
}  // namespace Strutil
}  // namespace OIIO
