/* Lab-only build override: libstrophe's src/common.h deliberately leaves
 * STROPHE_ASSERT and STROPHE_ASSERTVD user-definable. Defining them empty
 * reproduces the upstream claim that the only guard on SCRAM_Hi's salt
 * length is a compiled-out assertion. Stock builds are also exercised:
 * their NDEBUG macro returns early instead of overflowing. */
#ifndef LAB_NOASSERT_H
#define LAB_NOASSERT_H
#define STROPHE_ASSERT(x, r) ((void)0)
#define STROPHE_ASSERTVD(x) ((void)0)
#endif
