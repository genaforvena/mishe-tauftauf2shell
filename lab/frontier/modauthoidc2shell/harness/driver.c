/* Direct-call harness for CVE-2026-54789 / GHSA-vgr5-qcpp-x2pr.
 * oidc_state_cookies_parse_token() and the state-cookie record struct are
 * re-extracted verbatim from the pinned upstream blobs by run.sh into vuln/,
 * fixed/ and release/ slices. No Apache, no APR pool, no listener, no network: the
 * request/config types are opaque, the prefix getter, _oidc_strstr and the
 * downstream cookie processor are recording stubs. The token is a heap object
 * whose logical size is its strlen+1, so the unbounded scan has a measurable
 * boundary. Modes select advisory arithmetic, an exact-size ASan token, a
 * plain buffer with a chosen distance to a following '=' byte, and a
 * well-formed control.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef long apr_time_t;
typedef struct request_rec request_rec;
typedef struct oidc_cfg_t oidc_cfg_t;

#define OIDC_CHAR_SPACE ' '
#define OIDC_CHAR_EQUAL '='
#define OIDC_STR_SEMI_COLON ";"

static const char *g_prefix = "mod_auth_openidc_state_";
static int g_process_calls;
static int g_process_kept;
static char g_process_name[128];
static char g_process_value[128];

static char *_oidc_strstr(const char *h, const char *n) {
    return strstr(h, n);
}
static const char *oidc_cfg_dir_state_cookie_prefix_get(request_rec *r) {
    (void) r;
    return g_prefix;
}
static int oidc_state_cookies_process_one(request_rec *r, const oidc_cfg_t *c,
        char *cookieName, const char *value, const char *currentCookieName,
        struct oidc_state_cookies_t **first, struct oidc_state_cookies_t **last) {
    (void) r; (void) c; (void) currentCookieName; (void) first; (void) last;
    g_process_calls++;
    snprintf(g_process_name, sizeof(g_process_name), "%s", cookieName);
    snprintf(g_process_value, sizeof(g_process_value), "%s", value);
    g_process_kept = (value[0] != '\0');
    return g_process_kept;
}

#ifdef FIXED_VARIANT
#include "fixed/state_struct.inc"
#include "fixed/parse_token.inc"
#define VARIANT_NAME "fixed"
#elif defined(RELEASE_VARIANT)
#include "release/state_struct.inc"
#include "release/parse_token.inc"
#define VARIANT_NAME "release-v2.4.19.4"
#else
#include "vuln/state_struct.inc"
#include "vuln/parse_token.inc"
#define VARIANT_NAME "vuln"
#endif

#define BLOCK_CAP 512u
#define CANARY_OFF 400u
#define DEFAULT_GAP 17u

static const char *vtoken = "mod_auth_openidc_state_novalue";
static const char *stoken = "mod_auth_openidc_state_abc=1";

static void report(int rc, const char *mode, const char *tok,
                   unsigned long toklen, unsigned long alloc) {
    printf("VARIANT=%s MODE=%s RC=%d\n", VARIANT_NAME, mode, rc);
    printf("TOKEN=%s TOKEN_LEN=%lu TOKEN_ALLOC=%lu PREFIX_LEN=%lu\n",
           tok, toklen, alloc, (unsigned long) strlen(g_prefix));
    printf("PROCESS_CALLS=%d PROCESS_KEPT=%d PROCESS_NAME=%s PROCESS_VALUE=%s\n",
           g_process_calls, g_process_kept, g_process_name, g_process_value);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "arith";
    unsigned long gap = argc > 2 ? strtoul(argv[2], NULL, 10) : DEFAULT_GAP;
    size_t toklen = strlen(vtoken);
    char *block;
    int rc;

    if (strcmp(mode, "arith") == 0) {
        /* Advisory arithmetic only: no vulnerable function is called. */
        printf("VARIANT=%s MODE=arith\n", VARIANT_NAME);
        printf("PREFIX=%s PREFIX_LEN=%lu TOKEN=%s TOKEN_LEN=%zu\n",
               g_prefix, (unsigned long) strlen(g_prefix), vtoken, toklen);
        printf("TOKEN_HAS_EQUAL=0 SCAN_EXIT_CONDITION=EQUAL_ONLY "
               "NUL_INDEX=%zu BOUNDED_BY_NUL=0\n", toklen);
        printf("CHOSEN_GAP=%lu EXPECTED_NUL_OFFSET=%lu\n",
               gap, (unsigned long) (toklen + gap));
        return 0;
    }

    if (strcmp(mode, "eqscan") == 0) {
        /* Logical token object with a chosen-distance '=' in adjacent memory.
         * The scan is still relative to the token's NUL at TOKEN_LEN, so the
         * NUL write lands at TOKEN_LEN+gap in the enclosing block. */
        size_t eqoff;
        block = (char *) malloc(BLOCK_CAP);
        if (block == NULL) return 98;
        memset(block, 'A', BLOCK_CAP);
        memcpy(block, vtoken, toklen);
        block[toklen] = '\0';
        if (gap < 1u || gap > BLOCK_CAP - toklen - CANARY_OFF) {
            fprintf(stderr, "gap out of range\n");
            free(block);
            return 99;
        }
        eqoff = toklen + (size_t) gap;
        block[eqoff] = OIDC_CHAR_EQUAL;
        block[CANARY_OFF] = 'Z';
        rc = oidc_state_cookies_parse_token(NULL, NULL, block, NULL, NULL, NULL);
        printf("EQ_OFFSET=%zu BYTE_AT_EQ_OFFSET=%02x NUL_AT_OFFSET=%zu "
               "CANARY=%02x\n", eqoff, (unsigned char) block[eqoff],
               (block[eqoff] == '\0') ? eqoff : (size_t) 0,
               (unsigned char) block[CANARY_OFF]);
        report(rc, mode, vtoken, (unsigned long) toklen, BLOCK_CAP);
        free(block);
        return 0;
    }

    if (strcmp(mode, "asan-read") == 0) {
        /* Exact-size heap token: ASan must fault on the first read past it. */
        block = (char *) malloc(toklen + 1);
        if (block == NULL) return 98;
        memcpy(block, vtoken, toklen + 1);
        rc = oidc_state_cookies_parse_token(NULL, NULL, block, NULL, NULL, NULL);
        report(rc, mode, vtoken, (unsigned long) toklen,
               (unsigned long) (toklen + 1));
        free(block);
        return 0;
    }

    if (strcmp(mode, "safe") == 0) {
        /* Well-formed token: the '=' is inside the object in every variant. */
        size_t slen = strlen(stoken);
        block = (char *) malloc(slen + 1);
        if (block == NULL) return 98;
        memcpy(block, stoken, slen + 1);
        rc = oidc_state_cookies_parse_token(NULL, NULL, block, NULL, NULL, NULL);
        report(rc, mode, stoken, (unsigned long) slen,
               (unsigned long) (slen + 1));
        free(block);
        return 0;
    }

    fprintf(stderr, "usage: %s arith|eqscan [gap]|asan-read|safe\n", argv[0]);
    return 99;
}
