/* mtrace.c — synthetic LD_PRELOAD malloc/free tracer for ruby2shell Stage A.
 * Approved mechanism (operator standing approvals: "LD_PRELOAD mechanics
 * (synthetic-labeled)"). Logs every malloc/calloc/realloc/free with the
 * glibc chunk size read at free time, so a corrupted size LSB (0x53) is
 * captured before glibc's own checks abort the process.
 *
 * Hooks call __libc_malloc/__libc_free directly (no dlsym recursion).
 * Output: raw write(2) lines to fd from env MTRACE_FD (default 2).
 *   M <seq> <size> <ptr>
 *   C <seq> <count> <size> <ptr>
 *   R <seq> <oldptr> <newsize> <newptr>
 *   F <seq> <ptr> <sizefield-hex>   (sizefield = *(size_t*)(ptr-8))
 * Build: gcc -shared -fPIC -O2 -o mtrace.so mtrace.c
 */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void __libc_free(void *);

static int out_fd = 2;
static unsigned long seq = 0;

__attribute__((constructor))
static void mtrace_init(void)
{
    const char *fd_s = getenv("MTRACE_FD");
    if (fd_s)
        out_fd = atoi(fd_s);
}

static void emit(const char *tag, unsigned long a, unsigned long b,
                 unsigned long c)
{
    char buf[128];
    int len = snprintf(buf, sizeof buf, "%s %lu %lx %lx %lx\n",
                       tag, seq, a, b, c);
    if (len > 0)
        write(out_fd, buf, (size_t)len);
}

void *malloc(size_t size)
{
    void *p = __libc_malloc(size);
    emit("M", size, (unsigned long)(uintptr_t)p, 0);
    return p;
}

void *calloc(size_t n, size_t size)
{
    void *p = __libc_calloc(n, size);
    emit("C", n * size, (unsigned long)(uintptr_t)p, 0);
    return p;
}

void *realloc(void *old, size_t size)
{
    void *p = __libc_realloc(old, size);
    emit("R", (unsigned long)(uintptr_t)old, size,
         (unsigned long)(uintptr_t)p);
    return p;
}

void free(void *p)
{
    if (p)
        emit("F", (unsigned long)(uintptr_t)p,
             (unsigned long)*(size_t *)((char *)p - 8), 0);
    __libc_free(p);
}
