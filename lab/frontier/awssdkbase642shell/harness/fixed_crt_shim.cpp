// Lab-only shim for the fixed-CRT control: the real ApiAllocator lives in
// aws-crt-cpp's Api.cpp, which also pulls the IO/MQTT runtime. Base64 decoding
// only needs an aws-c-common allocator; the fixed CRT Types.cpp and common
// encoding/allocator/byte_buf/error sources are otherwise verbatim pinned.
#include <aws/crt/Allocator.h>
#include <aws/common/allocator.h>

namespace Aws
{
namespace Crt
{
Allocator *ApiAllocator() noexcept { return aws_default_allocator(); }
} // namespace Crt
} // namespace Aws

// Tiny support symbols from aws-c-common's platform layer; defining them here
// avoids linking the full library init/logging/thread stack, which the
// Base64-only path never calls.
#include <aws/common/zero.h>

#include <cstdio>
#include <cstring>

extern "C" void aws_debug_break(void) {}

extern "C" void aws_backtrace_print(FILE *, void *) {}

extern "C" void aws_secure_zero(void *buf, size_t len)
{
    std::memset(buf, 0, len);
}
