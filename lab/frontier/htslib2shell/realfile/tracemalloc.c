/* Minimal LD_PRELOAD allocation logger for the htslib OOB neighbour probe.
 * Logs size, returned pointer, and caller address; no heap layout changes
 * beyond the log buffer itself. Local lab diagnostic only. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int log_fd = -2;
static void logev(const char *kind, size_t n, void *p, void *caller) {
    if (log_fd == -2) log_fd = open("malloc-trace.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    char buf[192];
    int k = snprintf(buf, sizeof(buf), "%s %zu %p %p\n", kind, n, p, caller);
    if (k > 0) (void)write(log_fd, buf, (size_t)k);
}

void *malloc(size_t n) {
    static void *(*real)(size_t);
    if (!real) real = dlsym(RTLD_NEXT, "malloc");
    void *p = real(n);
    logev("M", n, p, __builtin_return_address(0));
    return p;
}

void *calloc(size_t a, size_t b) {
    static void *(*real)(size_t, size_t);
    if (!real) real = dlsym(RTLD_NEXT, "calloc");
    void *p = real(a, b);
    logev("C", a * b, p, __builtin_return_address(0));
    return p;
}

void *realloc(void *old, size_t n) {
    static void *(*real)(void *, size_t);
    if (!real) real = dlsym(RTLD_NEXT, "realloc");
    void *p = real(old, n);
    logev("R", n, p, __builtin_return_address(0));
    return p;
}
