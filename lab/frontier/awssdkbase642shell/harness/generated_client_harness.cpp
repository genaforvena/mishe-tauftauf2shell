// Frontier harness: the real generated REST-JSON client model parses a
// wire-format JSON payload and decodes its "data" blob through the pinned
// HashingUtils::Base64Decode -> Base64::Decode sink. No network I/O.
#include <aws/core/AmazonWebServiceResult.h>
#include <aws/core/utils/json/JsonSerializer.h>
#include <aws/rest-json-protocol/model/JsonBlobsResult.h>
#include <cstdlib>

#include <cstdio>

namespace Aws
{
void *Malloc(const char *, size_t size) { return std::malloc(size); }
void Free(void *ptr) { std::free(ptr); }
} // namespace Aws

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <wire-json>\n", argv[0]);
        return 2;
    }
    const Aws::String wire(argv[1]);
    const Aws::Utils::Json::JsonValue payload(wire);
    Aws::Http::HeaderValueCollection headers;
    const Aws::AmazonWebServiceResult<Aws::Utils::Json::JsonValue> result(payload, headers);
    const Aws::RestJsonProtocol::Model::JsonBlobsResult model(result);
    std::printf("decoded=%zu\n", model.GetData().GetLength());
    return 0;
}
