/*
 * wire_drdynvc_driver.c -- drive the REAL compiled xrdp 0.10.6 receive chain
 * from a wire-formatted RDP virtual-channel PDU:
 *
 *   TPKT -> X.224 DT -> MCS SendDataRequest -> (no security header)
 *   -> CHANNEL_PDU_HEADER -> DYNVC_DATA_FIRST -> xrdp_mm_drdynvc_data_first
 *
 * This is one step beyond real_drdynvc_driver.c, which calls
 * xrdp_channel_process() directly. Here the bytes are parsed by the real
 * xrdp_rdp_recv() / xrdp_sec_recv() / xrdp_mcs_recv() / xrdp_iso_recv()
 * functions, exactly as they would be on a TLS connection with the
 * security header absent (is_security_header_present = 0).
 *
 * The sink body is the exact xrdp_mm_drdynvc_data_first() body using real
 * trans_create/trans_get_out_s/out_uint8a, so ASan reports on the real
 * 8192-byte trans out buffer.
 *
 * Build (ASan):
 *   cc -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
 *     -I<SRC>/libxrdp -I<SRC>/common -I<SRC>/include -I<BUILD> \
 *     wire_drdynvc_driver.c <BUILD>/libxrdp/.libs/libxrdp.a \
 *     <BUILD>/common/.libs/libcommon.a -lssl -lcrypto -lpthread -ldl -lm \
 *     -o wire_drdynvc_driver
 *
 * Usage: wire_drdynvc_driver [payload_len] [declared_total]
 */
#include "config_ac.h"
#include "libxrdp.h"
#include "xrdp_constants.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define DYNVC_CHAN 1
#define PAYLOAD_LEN 8200

static int g_callback_calls = 0;
static int g_last_bytes = -1;

static int
sink_data_first(intptr_t id, int chan_id, char *data, int bytes, int total_bytes)
{
    struct trans *trans;
    struct stream *s;

    g_callback_calls++;
    g_last_bytes = bytes;
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
    out_uint32_le(s, 0);
    out_uint32_le(s, 8 + 8 + 4 + 4 + 4 + bytes);
    out_uint32_le(s, 17);
    out_uint32_le(s, 8 + 4 + 4 + 4 + bytes);
    out_uint32_le(s, 42);
    out_uint32_le(s, bytes);
    out_uint32_le(s, total_bytes);
    out_uint8a(s, data, bytes);
    s_mark_end(s);
    trans_write_copy(trans);
    trans_delete(trans);
    return 0;
}

int
main(int argc, char **argv)
{
    struct xrdp_channel chan;
    struct xrdp_mcs mcs;
    struct xrdp_iso iso;
    struct trans *trans;
    struct xrdp_sec sec;
    struct xrdp_rdp rdp;
    struct xrdp_session session;
    struct list *channel_list;
    struct mcs_channel_item item;
    struct stream *wire;
    int payload_len = (argc > 1) ? atoi(argv[1]) : PAYLOAD_LEN;
    int declared = (argc > 2) ? atoi(argv[2]) : payload_len;
    int body_len, mcs_data_len, tpkt_len, i, code = 0;
    int rv;

    memset(&chan, 0, sizeof(chan));
    memset(&mcs, 0, sizeof(mcs));
    memset(&iso, 0, sizeof(iso));
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
    mcs.iso_layer = &iso;
    mcs.expecting_channel_join_requests = 0;
    trans = trans_create(TRANS_MODE_UNIX, 8192, 8192);
    iso.trans = trans;

    sec.mcs_layer = &mcs;
    sec.rdp_layer = &rdp;
    sec.chan_layer = &chan;
    sec.is_security_header_present = 0;
    sec.crypt_level = CRYPT_LEVEL_NONE;
    rdp.sec_layer = &sec;
    rdp.session = &session;
    session.id = 1234;

    chan.sec_layer = &sec;
    chan.mcs_layer = &mcs;
    chan.drdynvc_channel_id = 0;
    chan.drdynvcs[DYNVC_CHAN].data_first = sink_data_first;

    body_len = 1 + 1 + 4 + payload_len; /* cmd, chan id, total_bytes, data */
    mcs_data_len = 8 + body_len;        /* CHANNEL_PDU_HEADER + DYNVC body */
    tpkt_len = 4 + 3 + 1 + 6 + mcs_data_len;

    make_stream(wire);
    init_stream(wire, tpkt_len + 16);

    /* TPKT */
    out_uint8(wire, 3);
    out_uint8(wire, 0);
    out_uint16_be(wire, tpkt_len);
    /* X.224 DT-TPDU */
    out_uint8(wire, 2);
    out_uint8(wire, ISO_PDU_DT);
    out_uint8(wire, 0x80);
    /* MCS SendDataRequest: appid 25 << 2, 2-byte PER length determinant */
    out_uint8(wire, MCS_SDRQ << 2);
    out_uint8(wire, 0);
    out_uint8(wire, 0);                       /* initiator (ignored) */
    out_uint8(wire, (MCS_GLOBAL_CHANNEL + 1) >> 8);
    out_uint8(wire, (MCS_GLOBAL_CHANNEL + 1) & 0xff);
    out_uint8(wire, 0);                       /* priority/segmentation/padding */
    out_uint8(wire, 0x80 | (mcs_data_len >> 8));
    out_uint8(wire, mcs_data_len & 0xff);
    /* CHANNEL_PDU_HEADER: total_length, flags FIRST|LAST */
    out_uint32_le(wire, body_len);
    out_uint32_le(wire, 3);
    /* DYNVC_DATA_FIRST: cmd 0x28, one-byte ChannelId, u32 LE total_bytes */
    out_uint8(wire, 0x28);
    out_uint8(wire, DYNVC_CHAN);
    out_uint32_le(wire, declared);
    for (i = 0; i < payload_len; i++)
    {
        out_uint8(wire, 0x41 + (i % 26));
    }
    s_mark_end(wire);
    wire->p = wire->data;
    trans->in_s = wire;

    rv = xrdp_rdp_recv(&rdp, wire, &code);

    printf("WIRE rv=%d code=%d callback_calls=%d bytes_seen=%d "
           "payload=%d declared=%d\n",
           rv, code, g_callback_calls, g_last_bytes, payload_len, declared);
    printf("RESULT: %s\n",
           (g_callback_calls == 1 && g_last_bytes == payload_len)
           ? "WIRE_DYNVC_SINK_REACHED" : "WIRE_PATH_FAILED");
    free_stream(wire);
    return 0;
}
