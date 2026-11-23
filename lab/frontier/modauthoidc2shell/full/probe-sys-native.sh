#!/usr/bin/env bash
# W15: full-module value-less state-cookie probe on a genuinely non-ASan
# system httpd/APR stack (no libasan in httpd or module). Loopback 18091 only;
# 18090 is reserved for the witness's concurrent replay. No shim, no
# LD_PRELOAD, no ptrace, no ASAN_OPTIONS, no forced execution.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/usr/sbin/apache2
VCONF="$HERE/httpd-sys.conf";        VERR="$HERE/error-sys.log"
FCONF="$HERE/httpd-sys-fixed.conf";  FERR="$HERE/error-sys-fixed.log"
URL=http://127.0.0.1:18091/protected
OUT="$HERE/evidence/sys-native"
mkdir -p "$OUT"
export LD_LIBRARY_PATH="$HERE/plain-prefix/lib"

stop() {
  "$HTTPD" -f "$VCONF" -k stop >/dev/null 2>&1 || true
  "$HTTPD" -f "$FCONF" -k stop >/dev/null 2>&1 || true
  sleep 2
}
trap stop EXIT

# label, config, error log, cookie, restarts, requests per restart
sweep() {
  label="$1" conf="$2" err="$3" cookie="$4" restarts="$5" n="$6"
  : > "$OUT/$label-results.txt"
  for r in $(seq 1 "$restarts"); do
    stop
    : > "$err"
    "$HTTPD" -f "$conf" -k start >"$OUT/$label-$r-start.out" 2>&1 || true
    sleep 2
    pid=$(cat "$HERE/$(basename "$conf" .conf).pid" 2>/dev/null || echo NOPID)
    ok=0
    for i in $(seq 1 "$n"); do
      code=$(curl -sS --max-time 6 -o /dev/null -w '%{http_code}' \
        -H "Cookie: $cookie" "$URL" 2>/dev/null || echo CURLERR)
      [ "$code" = 302 ] && ok=$((ok+1))
    done
    crashes=$(grep -c 'exit signal\|Segmentation fault' "$err" || true)
    printf '%s start=%s master=%s ok302=%s/%s faults=%s\n' \
      "$label" "$r" "$pid" "$ok" "$n" "$crashes" | tee -a "$OUT/$label-results.txt"
  done
  cp "$err" "$OUT/$label-error.log"
}

{
  echo "date: $(date -u +%FT%TZ)"
  echo "httpd: $(sha256sum "$HTTPD")"
  echo "vuln state.c: $(sha256sum "$HERE/src/mod_auth_openidc-sys/src/state.c")"
  echo "vuln module:  $(sha256sum "$HERE/src/mod_auth_openidc-sys/src/.libs/mod_auth_openidc.so")"
  echo "fixed state.c: $(sha256sum "$HERE/src/mod_auth_openidc-sys-fixed/src/state.c")"
  echo "fixed module:  $(sha256sum "$HERE/src/mod_auth_openidc-sys-fixed/src/.libs/mod_auth_openidc.so")"
  echo "--- httpd ldd (no asan expected) ---"
  ldd "$HTTPD" | grep -E 'asan|apr|libc\.so'
  echo "--- module ldd (no asan expected) ---"
  ldd "$HERE/src/mod_auth_openidc-sys/src/.libs/mod_auth_openidc.so" | grep -E 'asan|apr|cjose|jansson'
} > "$OUT/summary.txt"

PAD=$(printf 'a%.0s' $(seq 1 7800))
sweep vuln_bare_7800  "$VCONF" "$VERR" "mod_auth_openidc_state_$PAD" 4 12
sweep vuln_safe_7800  "$VCONF" "$VERR" "mod_auth_openidc_state_$PAD=1" 2 8
sweep fixed_bare_7800 "$FCONF" "$FERR" "mod_auth_openidc_state_$PAD" 2 8
cat "$OUT/summary.txt"
