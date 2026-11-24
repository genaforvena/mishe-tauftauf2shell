/* verbatim from ntop/n2n 854fbbe0 src/wire.c — see PROVENANCE.md */
#include "harness/types.h"
int decode_uint16 (uint16_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx) {

    if(*rem < 2) {
        return 0;
    }

    *out  = ( base[*idx] & 0xff ) << 8;
    *out |= ( base[1 + *idx] & 0xff );
    *idx += 2;
    *rem -= 2;

    return 2;
}
int decode_uint32 (uint32_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx) {

    if(*rem < 4) {
        return 0;
    }

    *out  = ( base[0 + *idx] & 0xff ) << 24;
    *out |= ( base[1 + *idx] & 0xff ) << 16;
    *out |= ( base[2 + *idx] & 0xff ) << 8;
    *out |= ( base[3 + *idx] & 0xff );
    *idx += 4;
    *rem -= 4;

    return 4;
}
int decode_buf (uint8_t * out,
                size_t bufsize,
                const uint8_t * base,
                size_t * rem,
                size_t * idx) {

    if(*rem < bufsize) {
        return 0;
    }

    memcpy(out, (base + *idx), bufsize);
    *idx += bufsize;
    *rem -= bufsize;

    return bufsize;
}
int decode_mac (n2n_mac_t out,
                const uint8_t * base,
                size_t * rem,
                size_t * idx) {

    return decode_buf(out, N2N_MAC_SIZE, base, rem, idx);
}
int decode_cookie (n2n_cookie_t * out,  /* cookies are typedef'd as uint32_t which needs to correspond to this code */
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx) {

    return decode_uint32(out, base, rem, idx);
}
int decode_REGISTER_SUPER_NAK (n2n_REGISTER_SUPER_NAK_t *nak,
                               const n2n_common_t *cmn, /* info on how to interpret it */
                               const uint8_t *base,
                               size_t *rem,
                               size_t *idx) {

    size_t retval = 0;
    memset(nak, 0, sizeof(n2n_REGISTER_SUPER_NAK_t));

    retval += decode_cookie(&nak->cookie, base, rem, idx);
    retval += decode_mac(nak->srcMac, base, rem, idx);

    retval += decode_uint16(&(nak->auth.scheme), base, rem, idx);
    retval += decode_uint16(&(nak->auth.token_size), base, rem, idx);
    /* token_size is read from the wire; bound it to the fixed-size
     * destination field auth.token before copying. */
    if(nak->auth.token_size > N2N_AUTH_MAX_TOKEN_SIZE) {
        return -1;
    }
    retval += decode_buf(nak->auth.token, nak->auth.token_size, base, rem, idx);

    return retval;
}
