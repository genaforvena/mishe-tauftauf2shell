#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void __libc_free(void *);

static int fd = 2;
static const char *arm_path;
static int armed;
static unsigned long text_lo, text_hi;
static int regex_only;
static int pair_only;
static unsigned long image_base;
static __thread int busy;
struct rec { void *p; size_t n; void *caller; };
#define NREC (1u << 18)
static struct rec recs[NREC];
static size_t nrec;
static const char hex[] = "0123456789abcdef";

static void puthex(char *dst, unsigned long v)
{
    for (int i = 15; i >= 0; --i) { dst[i] = hex[v & 15]; v >>= 4; }
}

static void line(char tag, void *p, size_t n, void *caller, int dump)
{
    if (!armed || busy || fd < 0) return;
    busy = 1;
    char b[320];
    int at = 0;
    b[at++] = tag; b[at++] = ' ';
    puthex(b + at, (unsigned long)p); at += 16;
    b[at++] = ' ';
    puthex(b + at, (unsigned long)n); at += 16;
    b[at++] = ' ';
    puthex(b + at, (unsigned long)caller); at += 16;
    if (dump && p) {
        unsigned long q[4];
        memcpy(q, p, sizeof q);
        for (int i = 0; i < 4; ++i) {
            b[at++] = ' ';
            puthex(b + at, q[i]); at += 16;
        }
    }
    b[at++] = '\n';
    ssize_t r;
    do { r = write(fd, b, (size_t)at); } while (r < 0);
    busy = 0;
}

static int interesting(void *caller)
{
    unsigned long c = (unsigned long)caller;
    if (!text_lo || c < text_lo || c >= text_hi) return 0;
    if (!regex_only) return 1;
    unsigned long off = c - text_lo;
    return off >= 0x100000 && off < 0x130000;
}
static int pair_alloc(void *caller)
{
    if (!pair_only || !image_base) return interesting(caller);
    unsigned long off = (unsigned long)caller - image_base;
    return off == 0x150fdc || off == 0x13f218 || off == 0x151cd1 || off == 0x150cd1;
}

static int pair_free(void *caller)
{
    if (!pair_only || !image_base) return interesting(caller);
    unsigned long off = (unsigned long)caller - image_base;
    return off == 0x154734 || off == 0x15473c || off == 0x1518c1 ||
           off == 0x1518c9 || off == 0x153ff2 || off == 0x153ffa || off == 0x151b1d;
}

static void forget(void *p)
{
    if (!p) return;
    for (size_t i = 0; i < nrec; ++i)
        if (recs[i].p == p) recs[i].p = 0;
}

static void remember(void *p, size_t n, void *caller)
{
    if (!p || n > 32) return;
    forget(p);
    if (nrec < NREC) recs[nrec++] = (struct rec){p, n, caller};
}

static struct rec *findrec(void *p)
{
    if (!p) return 0;
    for (size_t i = nrec; i > 0; --i)
        if (recs[i-1].p == p) return &recs[i-1];
    return 0;
}

__attribute__((constructor)) static void init(void)
{
    const char *s = getenv("REGTRACE_FD");
    if (s) fd = atoi(s);
    arm_path = getenv("REGTRACE_ARM");
    pair_only = getenv("REGTRACE_PAIR_ONLY") != NULL;
    int f = open("/proc/self/maps", O_RDONLY);
    if (f >= 0) {
        char b[65536];
        ssize_t n = read(f, b, sizeof(b)-1);
        close(f);
        if (n > 0) {
            b[n] = 0;
            char *save = 0;
            for (char *ln = strtok_r(b, "\n", &save); ln; ln = strtok_r(0, "\n", &save)) {
                unsigned long a, z, off;
                char perm[8];
                if (sscanf(ln, "%lx-%lx %7s %lx", &a, &z, perm, &off) == 4 &&
                    strstr(ln, "/bin/ruby")) {
                    if (off == 0) image_base = a;
                    if (perm[0] == 'r' && perm[2] == 'x') {
                        text_lo = a; text_hi = z; break;
                    }
                }
            }
        }
    }
}

void *malloc(size_t n)
{
    void *caller = __builtin_return_address(0);
    void *p = __libc_malloc(n);
    if (!armed && arm_path && access(arm_path, F_OK) == 0) armed = 1;
    if (armed && n <= 32 && pair_alloc(caller)) {
        remember(p, n, caller);
        line('M', p, n, caller, 0);
    }
    return p;
}

void *calloc(size_t a, size_t b)
{
    void *caller = __builtin_return_address(0);
    void *p = __libc_calloc(a, b);
    if (!armed && arm_path && access(arm_path, F_OK) == 0) armed = 1;
    if (armed && a*b <= 32 && pair_alloc(caller)) {
        remember(p, a*b, caller);
        line('C', p, a*b, caller, 0);
    }
    return p;
}

void *realloc(void *old, size_t n)
{
    void *caller = __builtin_return_address(0);
    void *p = __libc_realloc(old, n);
    if (!armed && arm_path && access(arm_path, F_OK) == 0) armed = 1;
    if (armed && n <= 64 && pair_alloc(caller)) {
        forget(old);
        remember(p, n, caller);
        line('R', p, n, caller, 0);
    }
    return p;
}

void free(void *p)
{
    void *caller = __builtin_return_address(0);
    int wanted = armed && pair_free(caller);
    struct rec *r = wanted ? findrec(p) : 0;
    if (r) {
        line('F', p, r->n, caller, 1);
        forget(p);
    }
    else if (wanted) {
        line('F', p, 0, caller, 0);
    }
    __libc_free(p);
}
