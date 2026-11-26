// Frontier-authored build shim: only the fopen wrapper used by libcineon.
#pragma once
#include <cstdio>

namespace OIIO {
namespace Filesystem {
inline FILE* fopen(const char* path, const char* mode) {
    return std::fopen(path, mode);
}
}  // namespace Filesystem
}  // namespace OIIO
