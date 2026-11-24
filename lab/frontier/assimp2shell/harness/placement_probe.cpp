// W4 throwaway-style probe, kept for reproducing the plain-glibc placement
// NEGATIVE recorded in placement/evidence/w4-negative.log. Not part of the
// PASS/FAIL harnesses. It feeds a crafted glTF document to the real importer
// and, on a build that returns a scene, dumps the malloc chunk header around
// mVertices[0]. It never modifies the library, input or allocator.
#include <assimp/Importer.hpp>
#include <assimp/scene.h>
#include <cstdio>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <malloc.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) return 65;
    std::ostringstream ss;
    ss << f.rdbuf();
    const std::string json = ss.str();
    Assimp::Importer importer;
    const aiScene *scene = importer.ReadFileFromMemory(json.data(), json.size(), 0, "gltf");
    printf("scene=%s err=%s\n", scene ? "ok" : "null", importer.GetErrorString());
    if (!scene || scene->mNumMeshes == 0) return 1;
    const aiMesh *mesh = scene->mMeshes[0];
    printf("vertices=%u\n", mesh->mNumVertices);
    const unsigned char *p = reinterpret_cast<const unsigned char *>(mesh->mVertices);
    printf("base=%p usable=%zu\n", (const void *)p, malloc_usable_size((void *)p));
    for (int off = -16; off < 48; off += 8) {
        uint64_t v = 0;
        for (int i = 7; i >= 0; --i) v = (v << 8) | p[off + i];
        printf("p%+d=%016llx\n", off, (unsigned long long)v);
    }
    fflush(stdout);
    return 0;
}
