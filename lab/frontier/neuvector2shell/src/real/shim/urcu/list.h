/* Minimal stand-in for liburcu-cds list macros, used ONLY to compile the
 * unmodified pinned NeuVector dpi_sig.c against its real headers. None of
 * these macros are in the vulnerable function's path. */
#ifndef NEUVECTOR2SHELL_SHIM_URCU_LIST_H
#define NEUVECTOR2SHELL_SHIM_URCU_LIST_H
#include <stddef.h>

struct cds_list_head {
    struct cds_list_head *next, *prev;
};

#define CDS_INIT_LIST_HEAD(ptr) do { \
    (ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

static inline void cds_list_add(struct cds_list_head *e, struct cds_list_head *h)
{
    e->prev = h; e->next = h->next; h->next->prev = e; h->next = e;
}
static inline void cds_list_add_tail(struct cds_list_head *e, struct cds_list_head *h)
{
    e->next = h; e->prev = h->prev; h->prev->next = e; h->prev = e;
}
static inline void cds_list_del(struct cds_list_head *e)
{
    e->prev->next = e->next; e->next->prev = e->prev;
    e->next = e; e->prev = e;
}
static inline int cds_list_empty(const struct cds_list_head *h)
{
    return h->next == h;
}
#define cds_list_entry(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#define cds_list_for_each_entry_safe(pos, tmp, head, member) \
    for (pos = cds_list_entry((head)->next, __typeof__(*pos), member), \
         tmp = cds_list_entry(pos->member.next, __typeof__(*pos), member); \
         &pos->member != (head); \
         pos = tmp, tmp = cds_list_entry(tmp->member.next, __typeof__(*pos), member))

#endif
