// Frontier harness for CVE-2026-19642: calls the pinned AWS SDK C++ Base64
// decoder directly with a CLI-supplied input. No network I/O.
#include <aws/core/utils/base64/Base64.h>

#include <cstdio>
#include <string>

// Lab-only allocator shim: the real AWS core allocator lives in a different
// translation unit of the SDK; malloc/free keep ASan's heap layout intact.
#include <cstdlib>
namespace Aws {
void *Malloc(const char *, size_t size) { return std::malloc(size); }
void Free(void *ptr) { std::free(ptr); }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <base64-input>\n", argv[0]);
        return 2;
    }
    const Aws::String input(argv[1]);
    const size_t calculated = Aws::Utils::Base64::Base64::CalculateBase64DecodedLength(input);
    const Aws::Utils::ByteBuffer out = Aws::Utils::Base64::Base64().Decode(input);
    std::printf("len=%zu calculated=%zu actual=%zu\n", input.length(), calculated, out.GetLength());
    return 0;
}
