#ifndef MISHE_ASAN_SHIM_H
#define MISHE_ASAN_SHIM_H

/* Only purpose: let the UNMODIFIED witness-replayed real_wire.c link into a
 * plain (non-ASan) build. The harness uses this callback solely to print an
 * extra diagnostic line on an ASan death; it has no role in the vulnerability
 * mechanics or in any plain-build observation. */
static inline void __asan_set_death_callback(void (*cb)(void))
{
    (void)cb;
}

#endif
