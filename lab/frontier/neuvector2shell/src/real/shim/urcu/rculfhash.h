/* Opaque rculfhash types for compiling pinned NeuVector dpi_sig.c. */
#ifndef NEUVECTOR2SHELL_SHIM_RCULFHASH_H
#define NEUVECTOR2SHELL_SHIM_RCULFHASH_H
struct cds_lfht;
struct cds_lfht_node { void *opaque[4]; };
struct cds_lfht_iter { struct cds_lfht_node *node; };
typedef int (*cds_lfht_match_fct)(struct cds_lfht_node *node, const void *key);
#define cds_lfht_for_each(ht, iter, node) for ((node) = NULL; (node) != NULL; )
#endif
