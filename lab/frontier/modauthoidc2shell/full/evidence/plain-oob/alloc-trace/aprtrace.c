#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

typedef struct apr_pool_t apr_pool_t;
typedef size_t apr_size_t;

static int fd = -1;
static uintptr_t lo, hi;

static void emit(char tag, uintptr_t a, uintptr_t b, uintptr_t c) {
    char buf[80]; int n = 0;
    buf[n++] = tag; buf[n++] = ' ';
    const char *hex = "0123456789abcdef";
    for (int shift = 60; shift >= 0; shift -= 4) buf[n++] = hex[(a >> shift) & 15];
    buf[n++] = ' ';
    for (int shift = 60; shift >= 0; shift -= 4) buf[n++] = hex[(b >> shift) & 15];
    buf[n++] = ' ';
    for (int shift = 60; shift >= 0; shift -= 4) buf[n++] = hex[(c >> shift) & 15];
    buf[n++] = '\n';
    if (fd >= 0) (void)write(fd, buf, (size_t)n);
}

__attribute__((constructor)) static void init(void) {
    const char *f = getenv("APRTRACE_FILE");
    const char *l = getenv("APRTRACE_LO");
    const char *h = getenv("APRTRACE_HI");
    if (f) fd = open(f, O_WRONLY | O_CREAT | O_APPEND, 0600);
    lo = l ? (uintptr_t)strtoull(l, 0, 0) : 0;
    hi = h ? (uintptr_t)strtoull(h, 0, 0) : ~(uintptr_t)0;
}

void *apr_palloc(apr_pool_t *p, apr_size_t size) {
    static void *(*real)(apr_pool_t *, apr_size_t);
    if (!real) real = dlsym(RTLD_NEXT, "apr_palloc");
    void *r = real(p, size);
    uintptr_t a = (uintptr_t)r;
    if (a >= lo && a < hi) emit('A', a, (uintptr_t)size, (uintptr_t)__builtin_return_address(0));
    return r;
}

void *apr_pcalloc(apr_pool_t *p, apr_size_t size) {
    static void *(*real)(apr_pool_t *, apr_size_t);
    if (!real) real = dlsym(RTLD_NEXT, "apr_pcalloc");
    void *r = real(p, size);
    uintptr_t a = (uintptr_t)r;
    if (a >= lo && a < hi) emit('C', a, (uintptr_t)size, (uintptr_t)__builtin_return_address(0));
    return r;
}
