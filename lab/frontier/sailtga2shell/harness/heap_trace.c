/* sailtga2shell w4 — OBSERVATIONAL malloc trace. No victim is placed and no
 * return value is changed: this only logs the real heap layout of the shipped
 * CLI so natural post-pixel objects can be identified. Uses write(2) only to
 * avoid recursion through stdio. Lab-only, rung-4 evidence. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void __libc_free(void *);

static int fd = -1;
static unsigned seq;
static int done;
static void *pixel;

__attribute__((constructor)) static void trace_init(void)
{
    const char *path = getenv("SAIL_HEAP_TRACE");
    if (path != NULL) {
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    }
}

static void emit(const char *tag, const void *p, size_t a, size_t b)
{
    if (fd < 0 || done) {
        return;
    }
    char buf[160];
    int n = snprintf(buf, sizeof(buf), "%04u %-7s p=%p a=%zu b=%zu\n", seq, tag, p, a, b);
    if (n > 0) {
        ssize_t ignored = write(fd, buf, (size_t)n);
        (void)ignored;
    }
}

void *malloc(size_t size)
{
    void *p = __libc_malloc(size);
    if (!done && seq < 200) {
        emit("malloc", p, size, 0);
        seq++;
        if (pixel == NULL && size == 256 && p != NULL) {
            pixel = p;
            char buf[128];
            int n = snprintf(buf, sizeof(buf), "---- first 256-byte allocation is candidate pixel: %p\n", p);
            ssize_t ignored = write(fd, buf, (size_t)n);
            (void)ignored;
        }
    }
    return p;
}

void *calloc(size_t n, size_t size)
{
    void *p = __libc_calloc(n, size);
    if (!done && seq < 200) {
        emit("calloc", p, n, size);
        seq++;
    }
    return p;
}

void *realloc(void *old, size_t size)
{
    void *p = __libc_realloc(old, size);
    if (!done && seq < 200) {
        emit("realloc", p, (size_t)old, size);
        seq++;
    }
    return p;
}

void free(void *p)
{
    if (!done && seq < 200) {
        emit("free", p, 0, 0);
    }
    __libc_free(p);
}
