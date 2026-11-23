/* Harness scaffolding: allocator macros used by pinned encparse.c.
 * Upstream reallocarray.h pulls in Xorg's Xfuncproto; this local stub keeps
 * the pinned parser bytes verbatim while making the harness standalone. */
#ifndef LF2S_REALLOCARRAY_STUB_H
#define LF2S_REALLOCARRAY_STUB_H
#include <stdint.h>
#include <stdlib.h>

static inline void *lf2s_reallocarray(void *p, size_t n, size_t s)
{
    if (s != 0 && n > SIZE_MAX / s)
        return NULL;
    return realloc(p, n * s);
}

#define Xreallocarray(p, n, s) lf2s_reallocarray((p), (size_t)(n), (size_t)(s))
#define Xmallocarray(n, s)     Xreallocarray(NULL, (n), (s))
#endif
