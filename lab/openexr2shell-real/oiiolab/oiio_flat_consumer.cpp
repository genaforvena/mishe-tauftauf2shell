// Advisory GHSA-98rx-qpfv-qcwv flat consumer: only ImageInput::open() and
// ImageInput::read_image(), no deep API and no spec.deep inspection.
#include <OpenImageIO/imageio.h>
#include <cstdio>
#include <vector>

int
main (int argc, char** argv)
{
    if (argc < 2) {
        std::fprintf (stderr, "usage: %s file.exr\n", argv[0]);
        return 2;
    }
    auto in = OIIO::ImageInput::open (argv[1]);
    if (!in) {
        std::printf ("OPEN failed\n");
        return 3;
    }
    const OIIO::ImageSpec& spec = in->spec ();
    std::printf ("OPEN w=%d h=%d c=%d deep=%d\n", spec.width, spec.height,
                 spec.nchannels, (int) spec.deep);
    std::vector<float> pixels ((size_t) spec.width * spec.height * spec.nchannels);
    bool ok = in->read_image (OIIO::TypeDesc::FLOAT, pixels.data ());
    std::printf ("READ ok=%d\n", (int) ok);
    in->close ();
    return ok ? 0 : 1;
}
