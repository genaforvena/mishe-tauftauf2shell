#!/usr/bin/env bash
# W15: one unauthenticated request per fresh non-ASan httpd start.
# Loopback 18091 only; 18090 stays free for the witness. No shim/preload/ptrace.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/usr/sbin/apache2
VCONF="$HERE/httpd-sys.conf";        VERR="$HERE/error-sys.log"
FCONF="$HERE/httpd-sys-fixed.conf";  FERR="$HERE/error-sys-fixed.log"
URL=http://127.0.0.1:18091/protected
OUT="$HERE/evidence/sys-native"
mkdir -p "$OUT"
export LD_LIBRARY_PATH="$HERE/plain-prefix/lib"
PAD=$(printf 'a%.0s' $(seq 1 7800))

stop() {
  "$HTTPD" -f "$VCONF" -k stop >/dev/null 2>&1 || true
  "$HTTPD" -f "$FCONF" -k stop >/dev/null 2>&1 || true
  sleep 2
}
trap stop EXIT

# label, conf, err, cookie, starts
one() {
  label="$1" conf="$2" err="$3" cookie="$4" starts="$5"
  : > "$OUT/$label-first.txt"
  for r in $(seq 1 "$starts"); do
    stop
    : > "$err"
    "$HTTPD" -f "$conf" -k start >"$OUT/$label-first-$r-start.out" 2>&1 || true
    sleep 2
    code=$(curl -sS --max-time 6 -o /dev/null -w '%{http_code}' \
      -H "Cookie: $cookie" "$URL" 2>/dev/null || echo CURLERR)
    sleep 2
    faults=$(grep -c 'exit signal' "$err" || true)
    printf '%s start=%s first_code=%s faults=%s\n' \
      "$label" "$r" "$code" "$faults" | tee -a "$OUT/$label-first.txt"
  done
  cp "$err" "$OUT/$label-first-error.log"
}

one vuln_bare  "$VCONF" "$VERR" "mod_auth_openidc_state_$PAD" 6
one vuln_safe  "$VCONF" "$VERR" "mod_auth_openidc_state_$PAD=1" 2
one fixed_bare "$FCONF" "$FERR" "mod_auth_openidc_state_$PAD" 2
