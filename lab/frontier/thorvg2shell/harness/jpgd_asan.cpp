/* Decoder-only harness for GHSA-mw4c-w54x-248r / CVE-2026-123367.
 * Calls the real ThorVG jpgd public API (jpgdHeader/jpgdDecompress/jpgdDelete)
 * on a real JPEG read from disk, with no renderer, canvas or network. */
#include <cstdio>
#include <cstdlib>
#include <vector>
#include "tvgJpgd.h"

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s file.jpg\n", argv[0]);
        return 2;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "open failed: %s\n", argv[1]);
        return 3;
    }
    if (fseek(f, 0, SEEK_END) != 0) return 3;
    long n = ftell(f);
    if (n <= 0 || fseek(f, 0, SEEK_SET) != 0) return 3;
    std::vector<char> data((size_t) n);
    if (fread(data.data(), 1, (size_t) n, f) != (size_t) n) return 4;
    fclose(f);

    int w = 0, h = 0;
    jpeg_decoder* decoder = jpgdHeader(data.data(), (int) data.size(), &w, &h);
    printf("header: decoder=%p width=%d height=%d\n", (void*) decoder, w, h);
    fflush(stdout);
    if (!decoder) return 5;

    unsigned char* pixels = jpgdDecompress(decoder);
    printf("decompress: pixels=%p\n", (void*) pixels);
    fflush(stdout);
    if (pixels) {
        printf("pixel0: %02x %02x %02x %02x\n", pixels[0], pixels[1], pixels[2], pixels[3]);
        fflush(stdout);
    }
    jpgdDelete(decoder);
    return pixels ? 0 : 6;
}
