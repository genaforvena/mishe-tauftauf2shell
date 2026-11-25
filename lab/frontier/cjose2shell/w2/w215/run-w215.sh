#!/bin/bash
# W215: real pre-auth bearer-lane adjacency at a 72-byte attacker-sized write.
# One request per fresh gdb/Aprocess; loopback 127.0.0.1:18444 (vulnerable) and
# :18445 (fixed) only. No listener is left behind.
set -eu
T=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
W2=$(CDPATH= cd -- "$T/.." && pwd)
GDBPIDS=""
FAIL=0
sed -e "s|@W2@|$W2|g" -e "s|@T@|$T|g" "$T/apache-w215.conf" > "$T/apache-vuln.run.conf"
mkdir -p "$T/evidence" "$T/run" "$T/cache" "$T/html" \
         "$T/fixed-cache" "$T/fixed-run"
ln -sfn "$W2/mod_auth_openidc-fixed" "$T/mod_auth_openidc-fixed"
sed "s|@HERE@|$T|g" "$W2/apache-oauth-bearer-fixed.conf" > "$T/apache-fixed.run.conf"
sed "s|@HERE@|$T|g" "$W2/gdb-oauth-bearer-fixed.cmd" > "$T/gdb-fixed.cmd"

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
    timeout 60 gdb -q -batch -x "$cmd" --args /usr/sbin/apache2 -f "$conf" -X \
        > "$out" 2>&1 &
    GDBPIDS="$GDBPIDS $!"
    for i in $(seq 1 150); do
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

for spec in ctrl:w215-ctrl:40 zero:w215-zero:80 ptr:w215-ptr:80 \
            ptr:w215-ptr-r2:80 ptr:w215-ptr-r3:80; do
    mode=${spec%%:*}; rest=${spec#*:}; tag=${rest%%:*}; len=${rest##*:}
    sed "s|@LOG@|$T/evidence/gdb-$tag.log|" "$T/gdb-w215.cmd" > "$T/gdb-$tag.cmd"
    start "$T/apache-vuln.run.conf" "$T/gdb-$tag.cmd" "$T/evidence/stdout-$tag.log" 18444
    W2_PORT=18444 W2_TAG="$tag" python3 "$T/probe-w215.py" "$mode" \
        > "$T/evidence/probe-$tag.log" 2>&1
    sleep 2
    stop
done

start "$T/apache-fixed.run.conf" "$T/gdb-fixed.cmd" \
      "$T/evidence/stdout-fixed80.log" 18445
W2_PORT=18445 W2_TAG=w215-fixed80 python3 "$T/probe-w215.py" ptr \
    > "$T/evidence/probe-w215-fixed80.log" 2>&1
sleep 2
stop


LOG="$T/evidence/gdb-w215-ptr.log"
check PTR_KW_RAW80 "$(grep -c 'W2E_KW_DECRYPT raw_len=80' "$LOG" || true)" 1
check PTR_POST_UNWRAP "$(grep -c W2E_POST_UNWRAP "$LOG" || true)" 1
check PTR_VALUE_PTR "$(grep -c '0x4141414141414141' "$LOG" || true)" 1
check PTR_NO_DEREF "$(grep -c -E 'W2E_STRCMP_PTR_HIT|Program received signal' "$LOG" || true)" 0
check PTR_401 "$(grep -c 'HTTP/1.1 401 Unauthorized' "$T/evidence/w215-ptr-ptr-response.bin" || true)" 1
check FIXED80_401 "$(grep -c 'HTTP/1.1 401 Unauthorized' "$T/evidence/w215-fixed80-ptr-response.bin" || true)" 1
for tag in w215-ptr-r2 w215-ptr-r3; do
    L="$T/evidence/gdb-$tag.log"
    check "$tag-PTR" "$(grep -c '0x4141414141414141' "$L" || true)" 1
    check "$tag-NODEREF" "$(grep -c -E 'W2E_STRCMP_PTR_HIT|Program received signal' "$L" || true)" 0
done
check CTRL_RAW40 "$(grep -c 'W2E_KW_DECRYPT raw_len=40' "$T/evidence/gdb-w215-ctrl.log" || true)" 1
check ZERO_RAW80 "$(grep -c 'W2E_KW_DECRYPT raw_len=80' "$T/evidence/gdb-w215-zero.log" || true)" 1
FLOG="$T/evidence/oauth-bearer-fixed-gdb.log"
check FIXED_REJECT599 "$(grep -c 'line: 599' "$T/evidence/oauth-bearer-fixed-apache_error.log" || true)" 1
check FIXED_NO_UNWRAP "$(grep -c W2BF_AES_UNWRAP_KEY_REACHED "$FLOG" || true)" 0
check FIXED_KW_REACHED "$(grep -c 'W2BF_AES_KW_DECRYPT_REACHED raw_len=80' "$FLOG" || true)" 1

printf 'REPLAY_W215: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
ss -ltn | grep -E ':1844[45] ' || echo NO_LISTENER_LEFT
[ "$FAIL" -eq 0 ]
