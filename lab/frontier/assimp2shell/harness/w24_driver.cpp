// W24: benign control-flow marker for the MAT4 Indexer stack overwrite.
//
// The pinned glTF 1.0 accessor path copies elemSize (64 here) bytes from the
// document into a 4-byte `T value` local in Accessor::Indexer::GetValue().
// This driver is linked -no-pie so the marker address is a literal chosen
// value in the crafted document. Calling the marker is a rung-4 lab marker,
// never a remote command and never an assertion about real-world exploitability.
#include <assimp/Importer.hpp>
#include <assimp/scene.h>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

extern "C" __attribute__((used)) void tauf_marker() {
    fputs("TAUF_MARKER_CALLED\n", stdout);
    fflush(stdout);
    std::_Exit(0);
}

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    printf("MARKER_ADDR=%p\n", reinterpret_cast<void *>(&tauf_marker));
    fflush(stdout);
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
    return scene ? 0 : 1;
}
