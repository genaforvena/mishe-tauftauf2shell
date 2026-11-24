// thorvg2shell W185: Lottie-asset reachability probe.
// Uses the real tvg::Animation consumer: Animation::picture()->load(...) on
// the pinned ThorVG library, then Animation::frame(1) to drive the loader's
// run() -> builder->update() -> LottieImage::get() ->
// Picture::load(asset.data, asset.size, asset.mimeType) -> jpgd.
// No direct jpgd call, no renderer canvas, no wire service in this probe.
#include <thorvg.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

int main(int argc, char** argv)
{
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s FILE lottie+json|--file\n", argv[0]);
        return 2;
    }
    const char* path = argv[1];
    const bool file_mode = !std::strcmp(argv[2], "--file");

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
    auto anim = tvg::Animation::gen();
    auto picture = anim->picture();
    auto load = file_mode ? picture->load(path)
                          : picture->load(buf.data(), static_cast<uint32_t>(buf.size()), "lottie+json");
    float w = 0, h = 0;
    picture->size(&w, &h);
    // frame() requests the loader task; with threads==0 it runs synchronously.
    auto frame = anim->frame(1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    float total = anim->totalFrame();
    std::printf("lottie_api%s: bytes=%zu load=%d frame=%d total=%.0f size=%.0fx%.0f\n",
                file_mode ? "_file" : "", buf.size(), static_cast<int>(load),
                static_cast<int>(frame), total, w, h);
    std::fflush(stdout);
    tvg::Initializer::term();
    return 0;
}
