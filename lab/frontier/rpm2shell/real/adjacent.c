/* Lab-only allocator seam: place a live pointer-bearing object after malloc(1). */
#include <stddef.h>

extern void *__libc_malloc(size_t size);
static char marker;

void *malloc(size_t size)
{
    void *value = __libc_malloc(size);
    if (size == 1 && value != NULL) {
        void *guard = __libc_malloc(64);
        if (guard != NULL)
            *(char **)guard = &marker;
    }
    return value;
}
