// Placement probe for CVE-2026-134861 on the real importer path.
//
// Feeds a crafted glTF 1.0 document to Assimp::Importer::ReadFileFromMemory,
// then inspects the aiMesh vertex array that ExtractData filled. With
// -DPLAIN_READ the bytes at and just past the logical array are dumped; that
// variant is only for the non-ASan build, where such a read is not itself an
// instrumentation violation. The ASan variant only reports scene status: any
// ASan report must come from the importer's own out-of-bounds memcpy.
#include <assimp/Importer.hpp>
#include <assimp/scene.h>
#include <assimp/postprocess.h>
#include <cstdio>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#ifdef PLAIN_READ
#include <malloc.h>
#endif

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) return 65;
    std::ostringstream ss;
    ss << f.rdbuf();
    const std::string json = ss.str();

    Assimp::Importer importer;
    const aiScene *scene = importer.ReadFileFromMemory(json.data(), json.size(), 0, "gltf");
    printf("case=%s scene=%s err=%s\n", argv[1],
           scene ? "ok" : "null", importer.GetErrorString());
    if (scene) {
        printf("meshes=%u\n", scene->mNumMeshes);
        if (scene->mNumMeshes > 0 && scene->mMeshes[0]->mNumVertices > 0) {
            const aiMesh *mesh = scene->mMeshes[0];
            const aiVector3D *v = mesh->mVertices;
            printf("vertices=%u\n", mesh->mNumVertices);
#ifdef PLAIN_READ
            const size_t logical = (size_t)mesh->mNumVertices * sizeof(aiVector3D);
            const unsigned char *p = reinterpret_cast<const unsigned char *>(v);
            printf("logical=%zu usable=%zu\n", logical, malloc_usable_size((void *)v));
            printf("v1=%08x %08x %08x\n",
                   (unsigned)v[1].x, (unsigned)v[1].y, (unsigned)v[1].z);
            printf("dump16=");
            for (size_t i = logical - 8; i < logical + 8; ++i) printf("%02x ", p[i]);
            printf("\n");
            printf("tail=%02x %02x %02x %02x\n",
                   p[logical], p[logical + 1], p[logical + 2], p[logical + 3]);
            const size_t usable = malloc_usable_size((void *)v);
            uint64_t nextsize = 0;
            for (int i = 7; i >= 0; --i)
                nextsize = (nextsize << 8) | p[usable + i];
            printf("nextsize=%016llx\n", (unsigned long long)nextsize);
#endif
        }
    }
    fflush(stdout);
    return scene ? 0 : 1;
}
