// thorvg2shell: real public-API consumer probe.
// Default: reads a JPEG from disk into memory, then calls
// tvg::Picture::load(data,size,"jpg") on the real pinned ThorVG library. This
// is the in-memory byte path a wire service would use (LoaderMgr::loader ->
// JpgLoader::open -> jpgdHeader, JpgLoader::read -> run -> jpgdDecompress).
// With --file: calls tvg::Picture::load(path) instead (plain .jpg claim).
// No direct jpgd call in either mode.
#include <thorvg.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s FILE [mime|--file]\n", argv[0]);
        return 2;
    }
    const char* path = argv[1];
    const char* mime = argc > 2 ? argv[2] : "jpg";
    const bool file_mode = argc > 2 && !std::strcmp(argv[2], "--file");

    std::FILE* f = std::fopen(path, "rb");
    if (!f) { std::perror("fopen"); return 2; }
    std::string buf;
    char chunk[8192];
    size_t n;
    while ((n = std::fread(chunk, 1, sizeof chunk, f)) > 0) buf.append(chunk, n);
    std::fclose(f);

    if (tvg::Initializer::init(0) != tvg::Result::Success) {
        std::fprintf(stderr, "init failed\n");
        return 2;
    }
    auto picture = tvg::Picture::gen();
    auto result = file_mode ? picture->load(path)
                            : picture->load(buf.data(), static_cast<uint32_t>(buf.size()), mime);
    float w = 0, h = 0;
    picture->size(&w, &h);
    std::printf("public_api%s: bytes=%zu load=%d size=%.0fx%.0f\n",
                file_mode ? "_file" : "", buf.size(), static_cast<int>(result), w, h);

    std::fflush(stdout);
    // Picture's destructor is protected; gen() objects are released via unref()
    // or by process exit. This probe is a short-lived process, so no delete.
    tvg::Initializer::term();
    return 0;
}
