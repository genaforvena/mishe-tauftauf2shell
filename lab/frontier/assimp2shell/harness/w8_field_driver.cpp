// W8: after the ASan callback lets the importer's own 64-byte MAT4/FLOAT copy
// finish, look for the document's OUT-OF-BOUNDS source bytes (offsets 40..55,
// mapped to destination offsets 40..55 of a 12-byte aiVector3D) in live aiMesh
// fields returned by ReadFileFromMemory. Instrumentation only: the pinned
// library and the document are untouched. A hit in a normal in-bounds array
// would not count; only bytes from the OOB part of this copy are searched.
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

static const char kMarker[] = "TAUFLIVE8MARKXYZ";
static const size_t kMarkerLen = sizeof(kMarker) - 1;
static unsigned long g_addr;

static void record_fault(const char *report) {
    if (g_addr) return;
    const char *p = strstr(report, "on address 0x");
    if (!p) return;
    g_addr = strtoul(p + 13, nullptr, 16);
    fprintf(stderr, "ASAN_CB addr=0x%lx\n", g_addr);
    // Report address is dest+16 in this case; the 64-byte copy spans
    // dest+0..63, so 80 bytes from the report address cover the whole copy.
    __asan_unpoison_memory_region(reinterpret_cast<void *>(g_addr), 80);
}

static void scan(const char *label, const void *base, size_t len) {
    if (!base || !len) return;
    if (__asan_region_is_poisoned(const_cast<void *>(base), len)) {
        printf("SKIP_POISON field=%s ptr=%p\n", label, base);
        return;
    }
    const unsigned char *p = static_cast<const unsigned char *>(base);
    for (size_t i = 0; i + kMarkerLen <= len; ++i) {
        if (!memcmp(p + i, kMarker, kMarkerLen)) {
            printf("LIVE_HIT field=%s ptr=%p off=%zu\n", label, base, i);
            return;
        }
    }
    printf("SCAN_CLEAN field=%s ptr=%p bytes=%zu\n", label, base, len);
}

static void locate(const char *label, void *addr) {
    char name[128] = {0};
    void *region = nullptr;
    size_t size = 0;
    const char *cat = __asan_locate_address(addr, name, sizeof(name), &region, &size);
    printf("LOCATE %s cat=%s region=%p size=%zu name=%s\n",
           label, cat ? cat : "?", region, size, name);
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
    printf("case=%s scene=%s err=%s\n", argv[1], scene ? "ok" : "null",
           importer.GetErrorString());
    fflush(stdout);
    // Later allocations inside ImportMeshes can re-poison the redzone the
    // report callback unpoisoned; restore addressability before inspection.
    if (g_addr) __asan_unpoison_memory_region(
        reinterpret_cast<void *>(g_addr - 32), 160);
    if (g_addr) {
        const unsigned char *b = reinterpret_cast<const unsigned char *>(g_addr);
        fprintf(stderr, "POST_WRITE addr=0x%lx at24=", g_addr);
        for (int i = 24; i < 40; ++i) fprintf(stderr, "%02x", b[i]);
        fprintf(stderr, "\n");
        locate("report", reinterpret_cast<void *>(g_addr));
        locate("dest+40", reinterpret_cast<void *>(g_addr + 24));
    }

    if (scene) {
        printf("meshes=%u\n", scene->mNumMeshes);
        for (unsigned m = 0; m < scene->mNumMeshes; ++m) {
            const aiMesh *mesh = scene->mMeshes[m];
            printf("mesh%u ptr=%p vertices=%u faces=%u\n", m,
                   static_cast<const void *>(mesh), mesh->mNumVertices, mesh->mNumFaces);
            char label[64];
            snprintf(label, sizeof(label), "mesh%u.struct", m);
            scan(label, mesh, sizeof(aiMesh));
            snprintf(label, sizeof(label), "mesh%u.mVertices", m);
            scan(label, mesh->mVertices, size_t(mesh->mNumVertices) * sizeof(aiVector3D));
            snprintf(label, sizeof(label), "mesh%u.mNormals", m);
            scan(label, mesh->mNormals, size_t(mesh->mNumVertices) * sizeof(aiVector3D));
            snprintf(label, sizeof(label), "mesh%u.mTangents", m);
            scan(label, mesh->mTangents, size_t(mesh->mNumVertices) * sizeof(aiVector3D));
            snprintf(label, sizeof(label), "mesh%u.mBitangents", m);
            scan(label, mesh->mBitangents, size_t(mesh->mNumVertices) * sizeof(aiVector3D));
            for (unsigned c = 0; c < AI_MAX_NUMBER_OF_COLOR_SETS; ++c) {
                snprintf(label, sizeof(label), "mesh%u.mColors%u", m, c);
                scan(label, mesh->mColors[c], size_t(mesh->mNumVertices) * sizeof(aiColor4D));
            }
            for (unsigned t = 0; t < AI_MAX_NUMBER_OF_TEXTURECOORDS; ++t) {
                snprintf(label, sizeof(label), "mesh%u.mTextureCoords%u", m, t);
                scan(label, mesh->mTextureCoords[t], size_t(mesh->mNumVertices) * sizeof(aiVector3D));
            }
            snprintf(label, sizeof(label), "mesh%u.mFaces", m);
            scan(label, mesh->mFaces, size_t(mesh->mNumFaces) * sizeof(aiFace));
            snprintf(label, sizeof(label), "mesh%u.mName", m);
            scan(label, mesh->mName.C_Str(), mesh->mName.length);
        }
        scan("scene.meshes", scene->mMeshes, size_t(scene->mNumMeshes) * sizeof(aiMesh *));
    }
    fflush(stdout);
    fflush(stderr);
    return scene ? 0 : 1;
}
