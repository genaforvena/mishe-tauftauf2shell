// Frontier-authored build shim: only the local-time helper used by libcineon.
#pragma once
#include <ctime>

namespace OIIO {
namespace Sysutil {
inline void get_local_time(const time_t* t, struct tm* out) {
#if defined(_WIN32)
    localtime_s(out, t);
#else
    localtime_r(t, out);
#endif
}
}  // namespace Sysutil
}  // namespace OIIO
