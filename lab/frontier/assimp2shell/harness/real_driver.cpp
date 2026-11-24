// Real-path driver: parse a crafted glTF 1.0 document through Assimp's public
// Importer API. Built against the pinned v6.0.6 library with ASan.
#include <assimp/Importer.hpp>
#include <assimp/scene.h>
#include <assimp/postprocess.h>
#include <cstdio>
#include <string>
#include <fstream>
#include <sstream>

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
    if (scene) {
        printf("meshes=%u\n", scene->mNumMeshes);
        for (unsigned i = 0; i < scene->mNumMeshes; ++i)
            printf("mesh%u vertices=%u faces=%u\n", i, scene->mMeshes[i]->mNumVertices, scene->mMeshes[i]->mNumFaces);
    }
    return scene ? 0 : 1;
}
