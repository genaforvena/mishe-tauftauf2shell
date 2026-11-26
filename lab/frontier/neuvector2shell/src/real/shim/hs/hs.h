/* Minimal hyperscan type shim for compiling the unmodified pinned
 * NeuVector dpi_sig.c. Only opaque types/constants used by headers and
 * by dpi_sig_bld's non-vulnerable paths are provided. */
#ifndef NEUVECTOR2SHELL_SHIM_HS_H
#define NEUVECTOR2SHELL_SHIM_HS_H
typedef struct hs_database hs_database_t;
typedef struct hs_scratch hs_scratch_t;
#define HS_FLAG_PREFILTER (1u << 10)
#endif
