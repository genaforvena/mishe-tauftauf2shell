/* Direct-call harness for GHSA-vrjv-f8gv-2h35 (ettercap gg_get_version).
 * The helper under test is re-extracted verbatim from pinned upstream bytes
 * into vuln/gg_get_version.inc or fixed/gg_get_version.inc by run.sh.
 * No ettercap build, no dissector loop, no listener, no network.
 */
#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

typedef uint32_t u_int32; /* ettercap's typedef from its own headers */
#ifdef FIXED_VARIANT
#include "fixed/gg_get_version.inc"
#define DEFAULT_BUFSZ 64
#else
#include "vuln/gg_get_version.inc"
#define DEFAULT_BUFSZ 30
#endif

static void call_helper(uint32_t v, char *s, size_t bufsz)
{
#ifdef FIXED_VARIANT
    gg_get_version((u_int32)v, s, bufsz);
#else
    (void)bufsz;
    gg_get_version((u_int32)v, s);
#endif
}

/* Advisory arithmetic, computed independently of the helper. */
static size_t advisory_len(uint32_t v)
{
    size_t n;
    switch (v & 0xffu) {
    case 0x2a: case 0x29: case 0x28:
    case 0x27: case 0x26: case 0x25:
    case 0x22: case 0x21: case 0x20:
    case 0x1e: case 0x1c: case 0x1b: case 0x19:
    case 0x17: case 0x16: case 0x15: case 0x14:
    case 0x11: case 0x10: case 0x0f: case 0x0b:
        n = 3; break;
    case 0x24:
        n = 8; break;
    case 0x18:
        n = 7; break;
    default: {
        /* "unknown (0x" = 11, %X digits = 1..8, ")" = 1 */
        uint32_t q = v;
        size_t digits = 1;
        while (q >= 16u) { q >>= 4; digits++; }
        n = 11 + digits + 1;
        break;
    }
    }
    if ((v & 0xf0000000u) == 0x40000000u) n += 12; /* " + has audio" */
    if ((v & 0x0f000000u) == 0x04000000u) n += 11; /* " + eraomnix" */
    return n;
}

static void dump_bytes(const char *label, const unsigned char *p,
                       size_t lo, size_t hi)
{
    size_t i;
    printf("%s=", label);
    for (i = lo; i <= hi; i++) printf("%02x", p[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "arith";
    uint32_t v = argc > 2 ? (uint32_t)strtoul(argv[2], NULL, 16) : 0x44000042u;
    size_t bufsz = argc > 3 ? (size_t)strtoul(argv[3], NULL, 10)
                            : (size_t)DEFAULT_BUFSZ;
    size_t alen = advisory_len(v);

    if (strcmp(mode, "arith") == 0) {
        unsigned char w[128];
        memset(w, 0xee, sizeof(w));
        call_helper(v, (char *)w, bufsz);
        size_t actual = strnlen((char *)w, sizeof(w));
        printf("VERSION_HEX=%08X\n", v);
        printf("ADVISORY_STR_LEN=%zu\n", alen);
        printf("ADVISORY_TOTAL_WITH_NUL=%zu\n", alen + 1);
        printf("CALLER_ALLOC=%zu\n", bufsz);
        printf("ADVISORY_OVERFLOW=%zu\n",
               alen + 1 > bufsz ? alen + 1 - bufsz : 0);
        printf("ACTUAL_STR_LEN=%zu\n", actual);
        printf("MATCH_ADVISORY=%d\n", actual == alen ? 1 : 0);
        return 0;
    }

    if (strcmp(mode, "plain") == 0 || strcmp(mode, "safe") == 0) {
        /* 128-byte workspace: first bufsz bytes model the caller's object,
         * the rest are an observable canary for the byte-exact write claim. */
        unsigned char *w = malloc(128);
        size_t len, oob_hi;
        if (!w) return 98;
        memset(w, 0xee, 128);
        call_helper(v, (char *)w, bufsz);
        len = strnlen((char *)w, 128);
        printf("VERSION_HEX=%08X\n", v);
        printf("BUFSZ=%zu\n", bufsz);
        printf("STR_LEN=%zu\n", len);
        if (len + 1 > bufsz) {
            printf("OOB_COUNT=%zu\n", len + 1 - bufsz);
            oob_hi = len < 128 ? len : 127;
            if (oob_hi >= bufsz && bufsz < 128)
                dump_bytes("OOB_BYTES", w, bufsz, oob_hi);
        } else {
            printf("OOB_COUNT=0\n");
        }
        if (len < 127) {
            printf("CANARY_AFTER_NUL=%02x\n", w[len + 1]);
        }
        if ((v & 0xffu) == 0x42u && len >= 19) {
            dump_bytes("HEX_DIGITS_OFFSET_11_18", w, 11, 18);
        }
        free(w);
        return 0;
    }

    if (strcmp(mode, "asan") == 0) {
        /* Exact caller-sized allocation: ASan redzone starts at bufsz. */
        char *s = calloc(1, bufsz);
        if (!s) return 98;
        printf("CALL_BUFSZ=%zu\n", bufsz);
        printf("VERSION_HEX=%08X\n", v);
        fflush(stdout);
        call_helper(v, s, bufsz);
        printf("STR_LEN=%zu\n", strnlen(s, bufsz));
        free(s);
        return 0;
    }

    fprintf(stderr, "usage: %s arith|plain|safe|asan [versionhex] [bufsz]\n",
            argv[0]);
    return 99;
}
