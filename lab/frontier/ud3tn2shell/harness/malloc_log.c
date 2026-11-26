/* Loopback-lab helper: log malloc/free sizes, pointers and caller IPs.
 * Build: gcc -shared -fPIC -O2 -o malloc_log.so malloc_log.c -ldl
 * Run the daemon with LD_PRELOAD=malloc_log.so MALLOC_LOG=/path/to/log.
 * Uses only write(2) and a stack buffer so logging cannot recurse into malloc.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static void *(*real_malloc)(size_t);
static void (*real_free)(void *);
static void *(*real_calloc)(size_t, size_t);
static void *(*real_realloc)(void *, size_t);
static int busy;

static void emit(char tag, uintptr_t a, uintptr_t b, uintptr_t caller)
{
    char buf[128];
    size_t n = 0;
    const char hex[] = "0123456789abcdef";
    buf[n++] = tag;
    for (int i = 0; i < 3; i++) {
        buf[n++] = ' ';
        for (int shift = 60; shift >= 0; shift -= 4)
            buf[n++] = hex[((a >> shift) & 15)];
        a = b;
        b = caller;
    }
    buf[n++] = '\n';
    const char *path = getenv("MALLOC_LOG");
    if (!path)
        return;
    static int fd = -2;
    if (fd == -2)
        fd = (int)syscall(SYS_open, path, 01 | 01000 | 0100, 0644);
    if (fd >= 0)
        (void)write(fd, buf, n);
}

void *malloc(size_t n)
{
    if (busy) {
        if (!real_malloc)
            real_malloc = dlsym(RTLD_NEXT, "malloc");
        return real_malloc(n);
    }
    busy = 1;
    if (!real_malloc)
        real_malloc = dlsym(RTLD_NEXT, "malloc");
    void *p = real_malloc(n);
    emit('M', (uintptr_t)n, (uintptr_t)p,
         (uintptr_t)__builtin_return_address(0));
    busy = 0;
    return p;
}

void free(void *p)
{
    if (busy || !p) {
        if (!real_free)
            real_free = dlsym(RTLD_NEXT, "free");
        real_free(p);
        return;
    }
    busy = 1;
    if (!real_free)
        real_free = dlsym(RTLD_NEXT, "free");
    emit('F', (uintptr_t)p, 0, (uintptr_t)__builtin_return_address(0));
    real_free(p);
    busy = 0;
}

void *calloc(size_t n, size_t s)
{
    if (busy) {
        if (!real_calloc)
            real_calloc = dlsym(RTLD_NEXT, "calloc");
        return real_calloc(n, s);
    }
    busy = 1;
    if (!real_calloc)
        real_calloc = dlsym(RTLD_NEXT, "calloc");
    void *p = real_calloc(n, s);
    emit('C', (uintptr_t)(n * s), (uintptr_t)p,
         (uintptr_t)__builtin_return_address(0));
    busy = 0;
    return p;
}

void *realloc(void *old, size_t n)
{
    if (busy) {
        if (!real_realloc)
            real_realloc = dlsym(RTLD_NEXT, "realloc");
        return real_realloc(old, n);
    }
    busy = 1;
    if (!real_realloc)
        real_realloc = dlsym(RTLD_NEXT, "realloc");
    void *p = real_realloc(old, n);
    emit('R', (uintptr_t)n, (uintptr_t)p,
         (uintptr_t)__builtin_return_address(0));
    busy = 0;
    return p;
}
