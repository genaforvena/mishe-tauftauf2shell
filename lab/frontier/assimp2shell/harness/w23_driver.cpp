// W23: read the live aiScene returned by the real importer and exit without
// running the Importer/Asset destructors, so the observation is not followed
// by an unrelated free abort. The crafted bytes all come from the static
// glTF document; this driver only prints fields and calls _Exit.
#include <assimp/Importer.hpp>
#include <assimp/scene.h>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) return 65;
    std::ostringstream ss;
    ss << f.rdbuf();
    const std::string json = ss.str();
    Assimp::Importer importer;
    const aiScene *scene = importer.ReadFileFromMemory(json.data(), json.size(), 0, "gltf");
    printf("case=%s scene=%s err=%s\n", argv[1], scene ? "ok" : "null", importer.GetErrorString());
    if (scene) {
        printf("meshes=%u\n", scene->mNumMeshes);
        if (scene->mNumMeshes > 0) {
            const aiMesh *m = scene->mMeshes[0];
            printf("ptr0=%p verts0=%u faces0=%u\n", (const void *)m,
                   m ? m->mNumVertices : 0u, m ? m->mNumFaces : 0u);
        }
    }
    fflush(stdout);
    _Exit(scene ? 0 : 1);
}
