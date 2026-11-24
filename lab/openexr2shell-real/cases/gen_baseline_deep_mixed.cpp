// W178: valid deep+ZSTD EXR with FLOAT channel "A" before HALF channel "Z"
// in decode order. One row, one sample per pixel; the forging script replaces
// the sample table with 32 samples on the last pixel.
#include <ImfChannelList.h>
#include <ImfDeepFrameBuffer.h>
#include <ImfDeepScanLineOutputFile.h>
#include <ImfHeader.h>
#include <ImfPartType.h>
#include <Imath/ImathBox.h>
#include <Imath/half.h>
#include <cstdio>
#include <vector>

using namespace Imf;
using namespace Imath;

int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s out.exr\n", argv[0]);
        return 1;
    }
    const int W = 64, H = 1, NS = 32;
    Header hdr(W, H);
    hdr.compression() = ZSTD_COMPRESSION;
    hdr.setType(DEEPSCANLINE);
    hdr.channels().insert("A", Channel(Imf::FLOAT));
    hdr.channels().insert("Z", Channel(Imf::HALF));
    hdr.dataWindow() = Box2i(V2i(0, 0), V2i(W - 1, H - 1));
    hdr.displayWindow() = Box2i(V2i(0, 0), V2i(W - 1, H - 1));

    std::vector<unsigned int> sampleCount(W, 1u);
    std::vector<float> zdata(W * NS, 0.25f);
    std::vector<half> hdata(W * NS, half(0.5f));
    std::vector<float*> zptrs(W);
    std::vector<half*> hptrs(W);
    for (int i = 0; i < W; ++i) {
        zptrs[i] = &zdata[(size_t) i * NS];
        hptrs[i] = &hdata[(size_t) i * NS];
    }

    DeepFrameBuffer fb;
    fb.insertSampleCountSlice(
        Slice(Imf::UINT, (char*) sampleCount.data(), sizeof(unsigned int), 0));
    fb.insert("A", DeepSlice(Imf::FLOAT, (char*) zptrs.data(),
                             sizeof(float*), 0, sizeof(float)));
    fb.insert("Z", DeepSlice(Imf::HALF, (char*) hptrs.data(),
                             sizeof(half*), 0, sizeof(half)));

    DeepScanLineOutputFile file(argv[1], hdr);
    file.setFrameBuffer(fb);
    file.writePixels(H);
    printf("wrote %s\n", argv[1]);
    return 0;
}
