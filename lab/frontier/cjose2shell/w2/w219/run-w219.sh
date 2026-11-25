#!/bin/bash
# W219: sweep the attacker-controlled `enc` header in the real unauthenticated
# bearer lane. Same lab KEK, same 152-byte raw encrypted_key / 144-byte chosen
# write; only the CEK size selected by _keylen_from_enc() changes. One fresh
# gdb-started Apache per case; loopback 127.0.0.1:18444 / :18445 only.
set -eu
T=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
W2=$(CDPATH= cd -- "$T/.." && pwd)
GDBPIDS=""
PASS=0
FAIL=0
mkdir -p "$T/evidence" "$T/run" "$T/cache" "$T/html" "$T/fixed-cache" "$T/fixed-run"
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
    timeout 90 gdb -q -batch -x "$cmd" --args /usr/sbin/apache2 -f "$conf" -X \
        > "$out" 2>&1 &
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

for spec in gcm128:A128GCM gcm256:A256GCM cbc384:A192CBC-HS384 cbc512:A256CBC-HS512 base:A128CBC-HS256; do
    tag=${spec%%:*}; enc=${spec#*:}
    sed "s|@LOG@|$T/evidence/gdb-$tag.log|" "$T/gdb-w219.cmd" > "$T/gdb-$tag.cmd"
    start "$T/apache-vuln.run.conf" "$T/gdb-$tag.cmd" "$T/evidence/stdout-$tag.log" 18444
    W2_PORT=18444 W2_TAG="w219-$tag" W2_ENC="$enc" timeout 30 python3 "$T/probe-w219.py" \
        > "$T/evidence/probe-$tag.log" 2>&1 || echo "PROBE_FAILED=$tag" >> "$T/evidence/probe-failures.log"
    sleep 2
    stop
    L="$T/evidence/gdb-$tag.log"
    check "${tag}_KW152" "$(grep -c 'W219_KW_DECRYPT raw_len=152' "$L" || true)" 1
    check "${tag}_UNWRAP" "$(grep -c W219_UNWRAP_KEY_REACHED "$L" || true)" 1
    check "${tag}_DUMP" "$(grep -c W219_POST_UNWRAP "$L" || true)" 1
done

sed "s|@HERE@|$T|g" "$W2/gdb-oauth-bearer-fixed.cmd" > "$T/gdb-fixed.cmd"
start "$T/apache-fixed.run.conf" "$T/gdb-fixed.cmd" "$T/evidence/stdout-fixed.log" 18445
W2_PORT=18445 W2_TAG=w219-fixed W2_ENC=A128CBC-HS256 timeout 30 python3 "$T/probe-w219.py" \
    > "$T/evidence/probe-fixed.log" 2>&1 || echo "PROBE_FAILED=fixed" >> "$T/evidence/probe-failures.log"
sleep 2
stop

FLOG="$T/evidence/oauth-bearer-fixed-gdb.log"
check FIXED_KW152 "$(grep -c 'W2BF_AES_KW_DECRYPT_REACHED raw_len=152' "$FLOG" || true)" 1
check FIXED_NO_UNWRAP "$(grep -c W2BF_AES_UNWRAP_KEY_REACHED "$FLOG" || true)" 0
check FIXED_REJECT599 "$(grep -c 'line: 599' "$T/evidence/oauth-bearer-fixed-apache_error.log" || true)" 1

for tag in gcm128 gcm256 cbc384 cbc512 base; do
    printf '%s: %s\n' "$tag" "$(grep -m1 'W219_POST_UNWRAP' "$T/evidence/gdb-$tag.log" || true)"
done
printf 'REPLAY_W219: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
ss -ltn | grep -E ':1844[45] ' || echo NO_LISTENER_LEFT
[ "$FAIL" -eq 0 ]
