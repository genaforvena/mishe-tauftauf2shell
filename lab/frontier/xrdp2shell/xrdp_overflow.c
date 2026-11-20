/*
 * Extracted harness for xrdp CVE-2026-44178 / GHSA-hh7r-2rmq-q4g4.
 *
 * Transcribes the relevant bytes of xrdp v0.10.6 (raw sha256
 * d743c53f0f2f85e2cd0abc861996887c248a8270ebc9d75697f7208dd63d10d2):
 *   xrdp/xrdp_mm.c:2318-2346 xrdp_mm_drdynvc_data_first  (28-byte header)
 *   xrdp/xrdp_mm.c:2351-2377 xrdp_mm_drdynvc_data        (24-byte header)
 *   xrdp/xrdp_mm.c:2763-2809 xrdp_mm_process_channel_data(26-byte header)
 *   common/trans.c:1026-1041 trans_get_out_s -> init_stream(out_s, size)
 *   common/parse.h:248-259   init_stream keeps existing data if size <= old
 *   common/parse.h:563-572   out_uint8a -> out_uint8p -> g_memcpy (no default check)
 *   xrdp/xrdp_mm.c:3135      chan_trans = trans_create(..., 8192, 8192)
 * The 0.10.6.1 fix (commit 43dc9c3b) replaces each trans_get_out_s(trans, 8192)
 * with an exact pdu_size allocation and rejects length > 65535.
 *
 * No sockets, no xrdp library, no network. The payload is synthesized client
 * data; the vulnerable sink copies it verbatim, with no special case for the
 * instrumentation bytes. Do_copy counts bytes past the logical 8192-byte
 * stream; in the ASan build the allocation is exactly 8192 bytes so the real
 * memcpy faults. Leaking the buffers at exit is deliberate: the OOB writes
 * corrupt allocator metadata, and the security observations never free them.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHAN_BUF 8192
#ifndef SAFE_BACKING
#define SAFE_BACKING 1048576
#endif

/* Only the fields used by the transcribed macros; layout is otherwise irrelevant. */
struct stream {
    char *p;
    char *end;
    char *data;
    int size;
};

struct trans {
    struct stream out_s;
};

static struct trans g_trans;
static long g_oob_writes;
static long g_first_oob = -1;
static long g_last_oob = -1;
static unsigned char *g_backing;

static void reset_metrics(void)
{
    g_oob_writes = 0;
    g_first_oob = -1;
    g_last_oob = -1;
}

static void init_trans(int exact)
{
    /* Non-ASan builds get a 1 MiB backing so simulated OOB copies are safe;
     * the logical stream size remains the real 8192. ASan gets exactly 8192. */
    size_t alloc = exact ? (size_t)CHAN_BUF : (size_t)SAFE_BACKING;
    g_backing = (unsigned char *)malloc(alloc);
    if (g_backing == NULL)
    {
        exit(2);
    }
    g_trans.out_s.data = (char *)g_backing;
    g_trans.out_s.size = CHAN_BUF;
    g_trans.out_s.p = g_trans.out_s.data;
    g_trans.out_s.end = g_trans.out_s.data;
}

/* common/parse.h:248-259 plus trans.c:1026-1041. */
static struct stream *trans_get_out_s(struct trans *self, int size)
{
    if (size > self->out_s.size)
    {
        /* init_stream frees and reallocs to the exact requested size. */
        self->out_s.data = (char *)malloc((size_t)size);
        if (self->out_s.data == NULL)
        {
            exit(2);
        }
        self->out_s.size = size;
    }
    self->out_s.p = self->out_s.data;
    self->out_s.end = self->out_s.data;
    return &self->out_s;
}

/* Instrumented g_memcpy from out_uint8p (parse.h:563-572). */
static void do_copy(struct stream *s, const void *src, int n)
{
    long off = (long)(s->p - s->data);
    long end = off + n;
#ifndef ASAN_BUILD
    if (end > s->size)
    {
        long first = off > s->size ? off : s->size;
        if (g_first_oob < 0 || first < g_first_oob)
        {
            g_first_oob = first;
        }
        if (end - 1 > g_last_oob)
        {
            g_last_oob = end - 1;
        }
        g_oob_writes += end - first;
    }
#endif
    memcpy(s->p, src, (size_t)n);
    s->p += n;
}

static void out_u32(struct stream *s, unsigned int v)
{
    unsigned char b[4] = {
        (unsigned char)(v & 0xff), (unsigned char)((v >> 8) & 0xff),
        (unsigned char)((v >> 16) & 0xff), (unsigned char)((v >> 24) & 0xff)
    };
    do_copy(s, b, 4);
}

static void out_u16(struct stream *s, unsigned int v)
{
    unsigned char b[2] = {
        (unsigned char)(v & 0xff), (unsigned char)((v >> 8) & 0xff)
    };
    do_copy(s, b, 2);
}

static void s_mark_end(struct stream *s)
{
    s->end = s->p;
}

/* xrdp_mm.c:2318-2346. fix=1 applies the 0.10.6.1 exact-size allocation. */
static void drdynvc_data_first(int bytes, const char *data, int fix)
{
    const int pdu_size = fix ? (8 + 8 + 4 + 4 + 4 + bytes) : CHAN_BUF;
    struct stream *s = trans_get_out_s(&g_trans, pdu_size);
    out_u32(s, 0);              /* version */
    out_u32(s, (unsigned int)(8 + 8 + 4 + 4 + 4 + bytes));
    out_u32(s, 17);             /* msg id */
    out_u32(s, (unsigned int)(8 + 4 + 4 + 4 + bytes));
    out_u32(s, 1);              /* chansrv_chan_id */
    out_u32(s, (unsigned int)bytes);
    out_u32(s, (unsigned int)bytes); /* total_bytes */
    do_copy(s, data, bytes);
    s_mark_end(s);
}

/* xrdp_mm.c:2351-2377. */
static void drdynvc_data(int bytes, const char *data, int fix)
{
    const int pdu_size = fix ? (8 + 8 + 4 + 4 + bytes) : CHAN_BUF;
    struct stream *s = trans_get_out_s(&g_trans, pdu_size);
    out_u32(s, 0);
    out_u32(s, (unsigned int)(8 + 8 + 4 + 4 + bytes));
    out_u32(s, 19);
    out_u32(s, (unsigned int)(8 + 4 + 4 + bytes));
    out_u32(s, 1);
    out_u32(s, (unsigned int)bytes);
    do_copy(s, data, bytes);
    s_mark_end(s);
}

/* xrdp_mm.c:2763-2809. The 0.10.6.1 fix also rejects length > 65535. */
static int process_channel_data(int length, const char *data, int fix)
{
    if (fix && length > 65535)
    {
        return 1;
    }
    const int pdu_size = fix ? (8 + 8 + 2 + 2 + 2 + 4 + length) : CHAN_BUF;
    struct stream *s = trans_get_out_s(&g_trans, pdu_size);
    out_u32(s, 0);
    out_u32(s, (unsigned int)(8 + 8 + 2 + 2 + 2 + 4 + length));
    out_u32(s, 5);
    out_u32(s, (unsigned int)(8 + 2 + 2 + 2 + 4 + length));
    out_u16(s, 1);              /* id */
    out_u16(s, 3);              /* flags */
    out_u16(s, (unsigned int)length);
    out_u32(s, (unsigned int)length); /* total_length */
    do_copy(s, data, length);
    s_mark_end(s);
    return 0;
}

#define PAYLOAD 20000
/* Deterministic client payload with two instrumentation markers. */
static void fill_payload(unsigned char *buf, int n, unsigned char m1, unsigned char m2)
{
    for (int i = 0; i < n; i++)
    {
        buf[i] = (unsigned char)(0x11 + (i % 0x70));
    }
    buf[8200] = m1;             /* lands at stream offset 28 + 8200 = 8228 */
    buf[12000] = m2;            /* lands at stream offset 28 + 12000 = 12028 */
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "rung1";
    int exact_alloc = (strcmp(mode, "rung3") == 0);
    init_trans(exact_alloc);
    reset_metrics();

    unsigned char *payload = (unsigned char *)malloc(PAYLOAD);
    if (payload == NULL)
    {
        return 2;
    }

    if (strcmp(mode, "rung1") == 0)
    {
        fill_payload(payload, PAYLOAD, 0xab, 0xcd);
        drdynvc_data_first(PAYLOAD, (char *)payload, 0);
        printf("rung1 header=28 copy_len=%d oob_writes=%ld first_oob=%ld last_oob=%ld\n",
               PAYLOAD, g_oob_writes, g_first_oob, g_last_oob);
    }
    else if (strcmp(mode, "static") == 0)
    {
        fill_payload(payload, PAYLOAD, 0xab, 0xcd);
        int rc = process_channel_data(PAYLOAD, (char *)payload, 0);
        printf("static header=26 copy_len=%d rc=%d oob_writes=%ld first_oob=%ld last_oob=%ld\n",
               PAYLOAD, rc, g_oob_writes, g_first_oob, g_last_oob);
    }
    else if (strcmp(mode, "rung2") == 0)
    {
        fill_payload(payload, PAYLOAD, 0xab, 0xcd);
        drdynvc_data_first(PAYLOAD, (char *)payload, 0);
        unsigned char a = g_backing[8228];
        unsigned char b = g_backing[12028];
        printf("rung2 marker1=0x%02x at oob=8228 marker2=0x%02x at oob=12028 oob_writes=%ld\n",
               a, b, g_oob_writes);
        return (a == 0xab && b == 0xcd) ? 0 : 1;
    }
    else if (strcmp(mode, "rung3") == 0)
    {
        /* Real 8192-byte malloc: the sink's memcpy must trip ASan. */
        fill_payload(payload, PAYLOAD, 0xab, 0xcd);
        drdynvc_data_first(PAYLOAD, (char *)payload, 0);
        printf("rung3 NO_ASAN_FAULT\n");
        return 3;
    }
    else if (strcmp(mode, "rung4") == 0)
    {
        /* Two independent client messages, two chosen markers, no sink special case. */
        fill_payload(payload, PAYLOAD, 0xde, 0x11);
        drdynvc_data_first(PAYLOAD, (char *)payload, 0);
        unsigned char a = g_backing[8228];
        reset_metrics();
        fill_payload(payload, PAYLOAD, 0x11, 0xad);
        drdynvc_data(PAYLOAD, (char *)payload, 0);
        unsigned char b = g_backing[12024]; /* data() header is 24, marker index 12000 */
        printf("rung4 call1=0x%02x at oob=8228 call2=0x%02x at oob=12024 oob_writes=%ld\n",
               a, b, g_oob_writes);
        return (a == 0xde && b == 0xad) ? 0 : 1;
    }
    else if (strcmp(mode, "fixed") == 0)
    {
        fill_payload(payload, PAYLOAD, 0xab, 0xcd);
        drdynvc_data_first(PAYLOAD, (char *)payload, 1);
        long first = g_oob_writes;
        reset_metrics();
        drdynvc_data(PAYLOAD, (char *)payload, 1);
        long second = g_oob_writes;
        reset_metrics();
        int rc = process_channel_data(PAYLOAD, (char *)payload, 1);
        printf("fixed data_first_oob=%ld data_oob=%ld channel_rc=%d channel_oob=%ld\n",
               first, second, rc, g_oob_writes);
    }
    else if (strcmp(mode, "benign") == 0)
    {
        fill_payload(payload, 100, 0xab, 0xcd);
        drdynvc_data_first(100, (char *)payload, 0);
        printf("benign oob_writes=%ld\n", g_oob_writes);
    }
    else
    {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }
    return 0;
}
