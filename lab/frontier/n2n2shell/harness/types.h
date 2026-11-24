#ifndef N2N_HARNESS_TYPES_H
#define N2N_HARNESS_TYPES_H

/* Stand-in types reproducing the layout of ntop/n2n dc7324af
 * include/n2n_typedefs.h:282,334-335,404-408. No runtime code copied. */
#include <stdint.h>
#include <stddef.h>

#define N2N_AUTH_MAX_TOKEN_SIZE 48
#define N2N_MAC_SIZE 6

typedef uint32_t n2n_cookie_t;
typedef uint8_t n2n_mac_t[N2N_MAC_SIZE];

typedef struct n2n_common {
    int unused;
} n2n_common_t;

typedef struct n2n_auth {
    uint16_t scheme;
    uint16_t token_size;
    uint8_t token[N2N_AUTH_MAX_TOKEN_SIZE];
} n2n_auth_t;

typedef struct n2n_REGISTER_SUPER_NAK {
    n2n_cookie_t cookie;
    n2n_mac_t srcMac;
    n2n_auth_t auth;
} n2n_REGISTER_SUPER_NAK_t;

#endif
