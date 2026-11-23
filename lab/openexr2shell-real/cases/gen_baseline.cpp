// Advisory-inlined generator: valid deep+ZSTD EXR, 64x1, one FLOAT channel.
#include <ImfDeepScanLineOutputFile.h>
#include <ImfHeader.h>
#include <ImfChannelList.h>
#include <ImfDeepFrameBuffer.h>
#include <ImfPartType.h>
#include <Imath/ImathBox.h>
#include <vector>
#include <cstdio>

using namespace Imf;
using namespace Imath;

int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s out.exr\n", argv[0]);
        return 1;
    }
    const int W = 64, H = 1;

    Header hdr(W, H);
    hdr.compression() = ZSTD_COMPRESSION;
    hdr.setType(DEEPSCANLINE);
    hdr.channels().insert("Z", Channel(Imf::FLOAT));
    hdr.dataWindow() = Box2i(V2i(0, 0), V2i(W - 1, H - 1));
    hdr.displayWindow() = Box2i(V2i(0, 0), V2i(W - 1, H - 1));

    DeepScanLineOutputFile file(argv[1], hdr);

    std::vector<unsigned int> sampleCount(W, 1u);
    std::vector<float> zdata(W, 1.0f);
    std::vector<float*> zptrs(W);
    for (int i = 0; i < W; ++i) zptrs[i] = &zdata[i];

    DeepFrameBuffer fb;
    fb.insertSampleCountSlice(
        Slice(Imf::UINT, (char*)sampleCount.data(), sizeof(unsigned int), 0));
    fb.insert("Z", DeepSlice(Imf::FLOAT, (char*)zptrs.data(),
                             sizeof(float*), 0, sizeof(float)));
    file.setFrameBuffer(fb);
    file.writePixels(H);
    printf("wrote %s\n", argv[1]);
    return 0;
}
