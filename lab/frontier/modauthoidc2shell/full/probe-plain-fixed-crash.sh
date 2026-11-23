#!/usr/bin/env bash
# Fixed-tag plain-module control for the 7800-byte bare state-token probe.
# Same loopback listener/port, one incident at a time. No gdb, no forced execution.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/apache2shell/build/httpd-2.4.70-install/bin/httpd
CONF="$HERE/httpd-plain-fixed.conf"
ERR="$HERE/error-plain-fixed.log"
URL=http://127.0.0.1:18090/protected
OUT="$HERE/evidence/plain-crash"
export LD_LIBRARY_PATH="$HERE/plain-prefix/lib"
mkdir -p "$OUT"
stop() { "$HTTPD" -f "$CONF" -k stop >/dev/null 2>&1 || true; sleep 1; }
trap stop EXIT
stop
: > "$ERR"
"$HTTPD" -f "$CONF" -k start >"$OUT/fixed-start.out" 2>&1
sleep 2
PAD=$(printf 'a%.0s' $(seq 1 7800))
: >"$OUT/fixed-codes.txt"
for mode in bare safe; do
  for trial in $(seq 1 10); do
    if [ "$mode" = bare ]; then cookie="mod_auth_openidc_state_$PAD"; else cookie="mod_auth_openidc_state_$PAD=1"; fi
    code=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' -H "Cookie: $cookie" "$URL" 2>/dev/null || echo CURLERR)
    printf '%s trial=%s code=%s\n' "$mode" "$trial" "$code" >>"$OUT/fixed-codes.txt"
  done
done
cp "$ERR" "$OUT/fixed-error.log"
{
  echo "state.c sha256: $(sha256sum "$HERE/src/mod_auth_openidc-plain-fixed/src/state.c" | awk '{print $1}')"
  echo "module sha256: $(sha256sum "$HERE/src/mod_auth_openidc-plain-fixed/src/.libs/mod_auth_openidc.so" | awk '{print $1}')"
  printf 'segments=%s empty=%s\n' "$(grep -ci 'segmentation fault\|exit signal' "$OUT/fixed-error.log" || true)" "$(grep -c 'code=000\|code=CURLERR' "$OUT/fixed-codes.txt" || true)"
} >"$OUT/fixed-summary.txt"
cat "$OUT/fixed-summary.txt"
