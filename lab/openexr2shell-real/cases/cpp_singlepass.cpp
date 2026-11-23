// Advisory's C++ single-pass path: readPixels() with no sample-count pre-pass.
#include <ImfDeepScanLineInputFile.h>
#include <ImfDeepFrameBuffer.h>
#include <ImfChannelList.h>
#include <ImfPartType.h>
#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace Imf;
using namespace Imath;

int
main (int argc, char** argv)
{
    if (argc < 2) return 2;
    const int W = 64, NSAMP = 1024;
    try {
        DeepScanLineInputFile file (argv[1]);
        std::vector<unsigned int> counts ((size_t) W * NSAMP, 0u);
        std::vector<float> data ((size_t) W * NSAMP, 0.f);
        std::vector<float*> ptrs (W);
        for (int i = 0; i < W; ++i) ptrs[i] = data.data () + (size_t) i * NSAMP;
        DeepFrameBuffer fb;
        fb.insertSampleCountSlice (
            Slice (Imf::UINT, (char*) counts.data (), sizeof (unsigned int), 0));
        fb.insert ("Z", DeepSlice (Imf::FLOAT, (char*) ptrs.data (),
                                   sizeof (float*), 0, sizeof (float)));
        file.setFrameBuffer (fb);
        file.readPixels (0, 0);
        printf ("READPIXELS ok rv=0\n");
        return 0;
    } catch (const std::exception& e) {
        printf ("READPIXELS exception: %s\n", e.what ());
        return 1;
    }
}
