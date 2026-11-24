// Real importer path with an ASan error-report callback. The callback records
// the reported out-of-bounds address and unpoisons it so that, with
// halt_on_error=0, the importer's own memcpy completes; main then dumps the
// live bytes after the copy. The library and the crafted input are unmodified.
#include <assimp/Importer.hpp>
#include <assimp/scene.h>
#include <assimp/postprocess.h>
#include <sanitizer/asan_interface.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

static unsigned long g_addr;
static void record_fault(const char *report) {
    const char *p = strstr(report, "on address 0x");
    if (!p) return;
    g_addr = strtoul(p + 13, nullptr, 16);
    fprintf(stderr, "ASAN_CB addr=0x%lx\n", g_addr);
    __asan_unpoison_memory_region(reinterpret_cast<void *>(g_addr), 16);
}

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    __asan_set_error_report_callback(record_fault);
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) return 65;
    std::ostringstream ss;
    ss << f.rdbuf();
    const std::string json = ss.str();
    Assimp::Importer importer;
    const aiScene *scene = importer.ReadFileFromMemory(json.data(), json.size(), 0, "gltf");
    printf("case=%s scene=%s err=%s\n", argv[1],
           scene ? "ok" : "null", importer.GetErrorString());
    if (g_addr) {
        const unsigned char *b = reinterpret_cast<const unsigned char *>(g_addr);
        __asan_unpoison_memory_region(reinterpret_cast<void *>(g_addr - 24), 40);
        fprintf(stderr, "POST_WRITE addr=0x%lx before24=", g_addr);
        for (int i = -24; i < 0; ++i) fprintf(stderr, "%02x", b[i]);
        fprintf(stderr, " at16=");
        for (int i = 0; i < 16; ++i) fprintf(stderr, "%02x", b[i]);
        fprintf(stderr, "\n");
    }
    fflush(stdout);
    fflush(stderr);
    return scene ? 0 : 1;
}
