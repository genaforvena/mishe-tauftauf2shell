/* jemtrace.c — LD_PRELOAD malloc tracer that observes jemalloc.
 *
 * Must be listed AFTER libjemalloc.so in LD_PRELOAD so dlsym(RTLD_NEXT, ...)
 * resolves to jemalloc:
 *   LD_PRELOAD="libjemalloc.so.2:./lab/preload/jemtrace.so"
 *
 * Logs compact M/C/R/F lines. When JEMTRACE_WATCH_SIZE is set, also dumps
 * eight qwords before and after the first eight allocations of that size.
 * No stdio/allocation inside the hooks: all output is raw write(2).
 *
 * JEMTRACE_TRACK_OVERFLOW=1 records the adjacent qword at allocation time and
 * emits O/P lines only when the watched free proves it changed to low byte 0x53.
 * JEMTRACE_SCAN_REFS=1 adds REF/D reference dumps; JEMTRACE_STOP_ON_OVERFLOW=1
 * raises SIGSTOP at the proven overwrite for an external debugger.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <signal.h>

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
static size_t bt_min;
static size_t bt_max;
static int want_bt;
static int want_bt_range;
static int bt_depth = 10;
static size_t free_q0;
static int free_all_q0;
static int track_overflow;
static int scan_overflow_refs;
static int stop_on_overflow;
static __thread void *overflow_ring_ptr[1024];
static __thread unsigned long overflow_ring_before[1024];
static __thread int overflow_ring_next;
unsigned long jemtrace_last_target;

static int want_bt_for(size_t sz)
{
    return (want_bt && bt_size && sz == bt_size) ||
           (want_bt_range && sz >= bt_min && sz <= bt_max);
}

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
static char overflow_mapbuf[262144];

/* Analysis-only: locate live references to the overwritten adjacent qword.
 * Called from free(2) after the write, with in_hook set; uses no allocation. */
static void
scan_overflow_references(unsigned long target)
{
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return;
    ssize_t n = read(fd, overflow_mapbuf, sizeof(overflow_mapbuf) - 1);
    close(fd);
    if (n <= 0) return;
    overflow_mapbuf[n] = 0;

    char *line = overflow_mapbuf;
    int found = 0;
    while (*line && found < 40) {
        char *next = strchr(line, '\n');
        if (next) *next++ = 0;
        unsigned long start, end;
        char perms[8];
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) == 3 &&
            perms[0] == 'r' && perms[1] == 'w' &&
            end > start && end - start <= 512UL * 1024 * 1024) {
            unsigned long pos = start;
            while (pos < end && found < 40) {
                unsigned long size = end - pos > 1048576 ? 1048576 : end - pos;
                unsigned char *hit = (unsigned char *)memmem((void *)pos, size, &target, 8);
                while (hit && found < 40) {
                    unsigned long ref = pos + (hit - (unsigned char *)pos);
                    char pbuf[17], sbuf[17];
                    rawhex(ref, pbuf); rawhex(target, sbuf);
                    rawex("REF", (unsigned long)syscall(SYS_gettid), pbuf, sbuf, NULL);
                    for (int k = -8; k < 8; k++) {
                        unsigned long at = ref + (long)k * 8;
                        if (at < start || at + 8 > end) continue;
                        unsigned long v = *(unsigned long *)at;
                        rawhex(at, pbuf); rawhex(v, sbuf);
                        rawex("D", (unsigned long)syscall(SYS_gettid), pbuf, sbuf, NULL);
                    }
                    found++;
                    unsigned long rest = pos + size - (unsigned long)(hit + 1);
                    hit = rest ? (unsigned char *)memmem(hit + 1, rest, &target, 8) : NULL;
                }
                pos += size;
            }
        }
        if (!next) break;
        line = next;
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
    const char *btminvar = getenv("JEMTRACE_BT_MIN");
    const char *btmaxvar = getenv("JEMTRACE_BT_MAX");
    const char *freevar = getenv("JEMTRACE_FREE_Q0");
    if (freevar) free_q0 = (size_t)strtoul(freevar, NULL, 0);
    free_all_q0 = getenv("JEMTRACE_FREE_ALL_Q0") != NULL;
    track_overflow = getenv("JEMTRACE_TRACK_OVERFLOW") != NULL;
    scan_overflow_refs = getenv("JEMTRACE_SCAN_REFS") != NULL;
    stop_on_overflow = getenv("JEMTRACE_STOP_ON_OVERFLOW") != NULL;
    const char *depthvar = getenv("JEMTRACE_BT_DEPTH"); if (depthvar) bt_depth = atoi(depthvar);
    if (btvar) { bt_size = (size_t)strtoul(btvar, NULL, 0); want_bt = 1; }
    if (btminvar || btmaxvar) {
        bt_min = btminvar ? (size_t)strtoul(btminvar, NULL, 0) : 0;
        bt_max = btmaxvar ? (size_t)strtoul(btmaxvar, NULL, 0) : (size_t)-1;
        want_bt_range = 1;
    }
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
    if (p && track_overflow && watch_size && sz == watch_size) {
        overflow_ring_ptr[overflow_ring_next] = p;
        overflow_ring_before[overflow_ring_next] =
            *(unsigned long *)((char *)p + sz);
        overflow_ring_next = (overflow_ring_next + 1) % 1024;
    }
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
    if (p && want_bt_for(sz)) emit_bt();
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
    if (p && want_bt_for(n * sz)) emit_bt();
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
    if (p && free_all_q0) {
        char pbuf[17], qbuf[17];
        rawhex((unsigned long)p, pbuf);
        rawhex(*(unsigned long *)p, qbuf);
        rawex("Q", (unsigned long)syscall(SYS_gettid), pbuf, qbuf, NULL);
    }
    if (p && free_q0 && *(size_t *)p == free_q0 && watch_size) {
        dump_window(p, watch_size, "before");
        dump_window(p, watch_size, "after");
        if (track_overflow) {
            unsigned long now = *(unsigned long *)((char *)p + watch_size);
            for (int i = 0; i < 1024; i++) {
                if (overflow_ring_ptr[i] == p) {
                    unsigned long before = overflow_ring_before[i];
                    if (now != before && (now & 0xff) == 0x53) {
                        unsigned long target = (unsigned long)p + watch_size;
                        char pbuf[17], sbuf[17];
                        jemtrace_last_target = target;
                        rawhex(target, pbuf); rawhex(now, sbuf);
                        rawex("O", (unsigned long)syscall(SYS_gettid), pbuf, sbuf, NULL);
                        rawhex(target, pbuf); rawhex(before, sbuf);
                        rawex("P", (unsigned long)syscall(SYS_gettid), pbuf, sbuf, NULL);
                        if (scan_overflow_refs) scan_overflow_references(target);
                        if (stop_on_overflow) raise(SIGSTOP);
                    }
                    break;
                }
            }
        }
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
