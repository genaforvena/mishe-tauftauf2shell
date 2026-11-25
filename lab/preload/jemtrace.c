/* jemtrace.c — LD_PRELOAD malloc tracer that observes jemalloc.
 *
 * Must be listed AFTER libjemalloc.so in LD_PRELOAD so dlsym(RTLD_NEXT, ...)
 * resolves to jemalloc:
 *   LD_PRELOAD="libjemalloc.so.2:./lab/preload/jemtrace.so"
 *
 * Logs compact M/C/R/F lines. When JEMTRACE_WATCH_SIZE is set, also dumps
 * eight qwords before and after the first eight allocations of that size.
 * No stdio/allocation inside the hooks: all output is raw write(2).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <execinfo.h>
extern void *__libc_malloc(size_t);
extern void __libc_free(void *);

static void *(*real_malloc)(size_t);
static void *(*real_calloc)(size_t, size_t);
static void *(*real_realloc)(void *, size_t);
static void (*real_free)(void *);
static size_t (*real_usable)(void *);
static int ready;
static int logfd = 2;
static size_t watch_size;
static int watch_count;
static __thread int in_hook;
static size_t arm_size;
static int armed;
static void *watch_ptr;
static size_t watch_sz;
static size_t post_size;
static size_t bt_size;
static int want_bt;
static int bt_depth = 10;
static size_t free_q0;

static const char hx[] = "0123456789abcdef";

static void rawex(const char *tag, unsigned long tid, const char *pbuf,
                  const char *sbuf, const char *extra)
{
    char buf[160];
    size_t i = 0;
    while (*tag) buf[i++] = *tag++;
    buf[i++] = ' ';
    if (!tid) buf[i++] = '0';
    else {
        char tmp[16]; size_t n = 0;
        unsigned long v = tid;
        while (v) { tmp[n++] = hx[v & 0xf]; v >>= 4; }
        while (n) buf[i++] = tmp[--n];
    }
    buf[i++] = ' '; buf[i++] = '0'; buf[i++] = 'x';
    memcpy(buf + i, pbuf, 16); i += 16;
    buf[i++] = ' '; buf[i++] = '0'; buf[i++] = 'x';
    memcpy(buf + i, sbuf, 16); i += 16;
    if (extra) while (*extra) buf[i++] = *extra++;
    buf[i++] = '\n';
    ssize_t r;
    do { r = write(logfd, buf, i); } while (r < 0);
}

static void rawhex(unsigned long v, char *out)
{
    int i;
    out[16] = 0;
    for (i = 15; i >= 0; i--) { out[i] = hx[v & 0xf]; v >>= 4; }
}

static void logline(const char *tag, size_t sz, void *p)
{
    char pbuf[17], sbuf[17];
    if (logfd < 0 || !ready) return;
    rawhex((unsigned long)p, pbuf);
    rawhex((unsigned long)sz, sbuf);
    rawex(tag, (unsigned long)syscall(SYS_gettid), pbuf, sbuf, NULL);
}

static void dump_window(void *base, size_t sz, const char *which)
{
    unsigned char *at = (unsigned char *)base;
    char pbuf[17], sbuf[17], extra[32];
    int i;
    if (which[0] == 'a') at += sz;
    rawhex((unsigned long)at, pbuf);
    for (i = 0; i < 8; i++) {
        unsigned long v = 0;
        memcpy(&v, at + i * 8, 8);
        rawhex(v, sbuf);
        extra[0] = ' ';
        extra[1] = which[0];
        extra[2] = '=';
        memcpy(extra + 3, sbuf, 16);
        extra[19] = 0;
        rawex("W", (unsigned long)syscall(SYS_gettid), pbuf, sbuf, extra);
    }
}

static void emit_bt(void)
{
    void *bt[24];
    int depth = bt_depth > 24 ? 24 : bt_depth;
    int n = backtrace(bt, depth);
    int k;
    for (k = 0; k < n; k++) {
        char buf[24];
        int len = snprintf(buf, sizeof(buf), "B %016lx\n",
                           (unsigned long)bt[k]);
        ssize_t r;
        do { r = write(logfd, buf, (size_t)len); } while (r < 0);
    }
}
__attribute__((constructor)) static void jemtrace_init(void)
{
    const char *fdvar = getenv("JEMTRACE_FD");
    const char *szvar = getenv("JEMTRACE_WATCH_SIZE");
    in_hook = 1;
    if (fdvar) logfd = atoi(fdvar);
    if (szvar) watch_size = (size_t)strtoul(szvar, NULL, 0);
    const char *btvar = getenv("JEMTRACE_BT_SIZE");
    const char *freevar = getenv("JEMTRACE_FREE_Q0");
    if (freevar) free_q0 = (size_t)strtoul(freevar, NULL, 0);
    const char *depthvar = getenv("JEMTRACE_BT_DEPTH"); if (depthvar) bt_depth = atoi(depthvar);
    if (btvar) { bt_size = (size_t)strtoul(btvar, NULL, 0); want_bt = 1; }
    const char *armvar = getenv("JEMTRACE_ARM_SIZE");
    if (armvar) arm_size = (size_t)strtoul(armvar, NULL, 0);
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    const char *postvar = getenv("JEMTRACE_POST_SIZE");
    if (postvar) post_size = (size_t)strtoul(postvar, NULL, 0);
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    real_free = dlsym(RTLD_NEXT, "free");
    real_usable = dlsym(RTLD_NEXT, "malloc_usable_size");
    if (!real_malloc) real_malloc = __libc_malloc;
    if (!real_free) real_free = __libc_free;
    in_hook = 0;
    ready = 1;
}

void *malloc(size_t sz)
{
    void *p;
    if (!ready || in_hook) return __libc_malloc(sz);
    in_hook = 1;
    p = real_malloc(sz);
    if (arm_size && sz == arm_size) armed = 1;
    if (armed && watch_size && sz == watch_size && watch_count < 8) {
        watch_count++;
        watch_ptr = p;
        watch_sz = sz;
        dump_window(p, sz, "before");
        dump_window(p, sz, "after");
    }
    if (post_size && sz == post_size && watch_ptr) {
        dump_window(watch_ptr, watch_sz, "before");
        dump_window(watch_ptr, watch_sz, "after");
        watch_ptr = NULL;
    }
    if (want_bt && bt_size && sz == bt_size && p) emit_bt();
    logline("M", sz, p);
    in_hook = 0;
    return p;
}

void *calloc(size_t n, size_t sz)
{
    void *p;
    if (!ready || in_hook) return __libc_malloc(n * sz);
    in_hook = 1;
    p = real_calloc ? real_calloc(n, sz) : NULL;
    if (p && !real_calloc) memset(p, 0, n * sz);
    logline("C", n * sz, p);
    if (want_bt && bt_size && n * sz == bt_size && p) emit_bt();
    in_hook = 0;
    return p;
}

void *realloc(void *old, size_t sz)
{
    void *p;
    if (!ready || in_hook) return NULL;
    in_hook = 1;
    p = real_realloc ? real_realloc(old, sz) : NULL;
    logline("R", sz, p);
    in_hook = 0;
    return p;
}

void free(void *p)
{
    if (!ready || in_hook) { __libc_free(p); return; }
    in_hook = 1;
    if (p && free_q0 && *(size_t *)p == free_q0 && watch_size) {
        dump_window(p, watch_size, "before");
        dump_window(p, watch_size, "after");
    }
    real_free(p);
    logline("F", 0, p);
    in_hook = 0;
}

size_t malloc_usable_size(void *p)
{
    if (!ready || in_hook || !real_usable) return 0;
    return real_usable(p);
}
