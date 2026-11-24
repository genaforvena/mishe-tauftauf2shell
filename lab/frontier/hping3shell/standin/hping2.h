/* Stand-in declarations for the verbatim pinned display_ipopt.c.
 * Constants and struct myiphdr are copied from pinned/hping2.h
 * (upstream commit 3547c7691742c6eaa31f8402e0ccbb81387c1b99, lines
 * 145-174 and 253-273). No other hping symbols are used by the
 * pinned function. */
#ifndef HPING2_STANDIN_H
#define HPING2_STANDIN_H

#include <stdint.h>

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;

/* Bits of the option type byte (verbatim). */
#define IPOPT_COPY              0x80
#define IPOPT_CLASS_MASK        0x60
#define IPOPT_NUMBER_MASK       0x1f
#define IPOPT_CONTROL           0x00
#define IPOPT_LSRR              (3 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_RR                (7 |IPOPT_CONTROL)
#define IPOPT_NOP               (1 |IPOPT_CONTROL)
#define IPOPT_EOL               (0 |IPOPT_CONTROL)
#define IPOPT_MINOFF            4
#define MAX_IPOPTLEN            40

/* struct myiphdr verbatim, little-endian bitfield branch. */
struct myiphdr {
        __u8    ihl:4,
                version:4;
        __u8    tos;
        __u16   tot_len;
        __u16   id;
        __u16   frag_off;
        __u8    ttl;
        __u8    protocol;
        __u16   check;
        __u32   saddr;
        __u32   daddr;
};

#endif
