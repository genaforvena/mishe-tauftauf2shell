#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>

/*
 * Targeted malloc/calloc/realloc failure injection for lab reproductions.
 *
 * Build: gcc -shared -fPIC -O2 -Wall -Wextra -o failmalloc.so failmalloc.c -ldl
 * FAILMALLOC_ARM          optional gate file; no failure before it exists
 * FAILMALLOC_TRIGGER_SIZE optional allocation size that starts counting
 * FAILMALLOC_SIZE         allocation size to count; zero counts every size
 * FAILMALLOC_COUNT        fail on this matching allocation (one-based)
 *
 * The trigger allocation itself is not counted. After the first failure the
 * interposer becomes passive, so callers see one ENOMEM and no extra layout
 * perturbation from repeated injected failures.
 */

static void *(*real_malloc)(size_t);
static void *(*real_calloc)(size_t, size_t);
static void *(*real_realloc)(void *, size_t);
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);

static const char *arm_path;
static long fail_at;
static size_t fail_size;
static size_t trigger_size;
static long count;
static int triggered;
static int failed;
static int ready;
static __thread int busy;

__attribute__((constructor)) static void init(void)
{
    const char *value;
    arm_path = getenv("FAILMALLOC_ARM");
    value = getenv("FAILMALLOC_COUNT");
    if (value) fail_at = strtol(value, 0, 0);
    value = getenv("FAILMALLOC_SIZE");
    if (value) fail_size = (size_t)strtoull(value, 0, 0);
    value = getenv("FAILMALLOC_TRIGGER_SIZE");
    if (value) trigger_size = (size_t)strtoull(value, 0, 0);
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    ready = real_malloc && real_calloc && real_realloc;
}

static int should_fail(size_t size)
{
    if (!ready || failed || fail_at <= 0) return 0;
    if (arm_path && access(arm_path, F_OK) != 0) return 0;
    if (trigger_size) {
        if (!triggered) {
            if (size == trigger_size) triggered = 1;
            return 0;
        }
    }
    if (fail_size && size != fail_size) return 0;
    count++;
    if (count == fail_at) {
        failed = 1;
        errno = ENOMEM;
        return 1;
    }
    return 0;
}

void *malloc(size_t size)
{
    if (!ready || busy) return __libc_malloc(size);
    busy = 1;
    if (should_fail(size)) {
        busy = 0;
        return NULL;
    }
    void *ptr = real_malloc(size);
    busy = 0;
    return ptr;
}

void *calloc(size_t count, size_t size)
{
    if (!ready || busy) return __libc_calloc(count, size);
    busy = 1;
    if (size && count > SIZE_MAX / size) {
        busy = 0;
        errno = ENOMEM;
        return NULL;
    }
    if (should_fail(count * size)) {
        busy = 0;
        return NULL;
    }
    void *ptr = real_calloc(count, size);
    busy = 0;
    return ptr;
}

void *realloc(void *old, size_t size)
{
    if (!ready || busy) return __libc_realloc(old, size);
    busy = 1;
    if (should_fail(size)) {
        busy = 0;
        return NULL;
    }
    void *ptr = real_realloc(old, size);
    busy = 0;
    return ptr;
}
