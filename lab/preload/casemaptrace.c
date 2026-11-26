/* Lab-only allocation tracer for the combined Regexp/casemap lane.
 * Build: gcc -shared -fPIC -O2 -Wall -Wextra -o casemaptrace.so casemaptrace.c
 * CASMAPTRACE_ARM=<file> enables logging once <file> exists (after boot).
 * Lines: "M <ptr> <req> <caller>" for 40..160-byte mallocs,
 *        "F <ptr> <chunksize> <caller>" for frees of 0x20-class chunks.
 * Addresses are raw glibc user pointers; no writes are performed.
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

extern void *__libc_malloc(size_t);
extern void __libc_free(void *);
extern void *__libc_realloc(void *, size_t);
extern size_t malloc_usable_size(void *);

static const char *arm_path;
static int armed;
static __thread int busy;

__attribute__((constructor)) static void init(void)
{
    arm_path = getenv("CASMAPTRACE_ARM");
}

static void check_arm(void)
{
    if (!armed && arm_path && access(arm_path, F_OK) == 0) armed = 1;
}

static void emit(char tag, void *p, size_t n, void *caller)
{
    if (!armed || busy) return;
    busy = 1;
    char b[96];
    int k = snprintf(b, sizeof b, "%c %p %zu %p\n", tag, p, n, caller);
    if (k > 0) (void)!write(2, b, (size_t)k);
    busy = 0;
}

void *malloc(size_t n)
{
    void *caller = __builtin_return_address(0);
    void *p = __libc_malloc(n);
    check_arm();
    if (armed && n >= 40 && n <= 160) emit('M', p, n, caller);
    return p;
}

void *realloc(void *old, size_t n)
{
    void *caller = __builtin_return_address(0);
    void *p = __libc_realloc(old, n);
    check_arm();
    if (armed && n >= 40 && n <= 160) emit('R', p, n, caller);
    return p;
}

void free(void *p)
{
    void *caller = __builtin_return_address(0);
    size_t chunk = p ? malloc_usable_size(p) + 8 : 0;
    if (armed && chunk == 32) emit('F', p, chunk, caller);
    __libc_free(p);
}
