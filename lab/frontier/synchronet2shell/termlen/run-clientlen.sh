#!/usr/bin/env bash
# W11 bounded probe: close W8's residual that the exact pty-req TERM byte
# count was not decoded. The paramiko client below records the exact TERM
# string it hands to transport encryption; the server is W8's verbatim W3
# wire/ssh_server6.c with only the port and getter buffer changed by the same
# recorded build-time sed. All traffic stays on 127.0.0.1. No Synchronet or
# cryptlib source is edited; this is an author measurement, not a witness
# verdict, and it does not change the vulnerability grade.
set -uo pipefail
cd "$(dirname "$0")"
ROOT=../src-tree/3rdp/src/cl
LIB=$ROOT/libcl.a
PY=../provision/local-py
test -f "$LIB" && test -f "$PY/paramiko/channel.py" || { echo MISSING_PREREQ; exit 2; }

if [ ! -x ./term_server ]; then
    sed -e 's/#define PORT 22222/#define PORT 22227/' \
        -e 's/char probe\[128\]/char probe[4096]/' \
        ../wire/ssh_server6.c > term_server.c
    gcc -g -O0 -I"$ROOT" term_server.c "$LIB" -lpthread -o term_server || exit 3
fi

mkdir -p evidence/clientlen
{
    echo "probe: W8 verbatim ../wire/ssh_server6.c via recorded build-time sed"
    echo "sed: -e s/#define PORT 22222/#define PORT 22227/ -e s/char probe[128]/char probe[4096]/"
    echo "client: term_client.py records paramiko pty-req TERM before encryption"
    sha256sum term_client.py run-clientlen.sh "$PY/paramiko/channel.py" \
        ../wire/ssh_server6.c "$LIB" "$ROOT/session/ssh2_msgsvr.c" \
        "$ROOT/enc_dec/misc_rw.c" "$ROOT/cryptlib.h"
} > evidence/clientlen/provenance.txt

pass=0
fail=0

run_case() {
    local n=$1 seconds=$2
    local out="evidence/clientlen/term${n}.out"
    local client="evidence/clientlen/term${n}-client.log"
    local pid rc

    pgrep -f '/termlen/term_server$' | xargs -r kill 2>/dev/null
    : > "$out"
    ./term_server > "$out" 2>&1 &
    pid=$!
    sleep 1
    PYTHONPATH="$PY" timeout $((seconds + 10)) python3 term_client.py \
        --port 22227 --term-length "$n" --seconds "$seconds" > "$client" 2>&1
    rc=$?
    wait "$pid" 2>/dev/null
    echo "run_case n=$n client_rc=$rc"

    if [ "$rc" -eq 0 ] && grep -q "PASS exact wire TERM length $n" "$client"; then
        echo "PASS n=$n client handed exactly $n TERM bytes to the transport"
        pass=$((pass + 1))
    else
        echo "FAIL n=$n client did not send exactly $n TERM bytes (rc=$rc; $client)"
        fail=$((fail + 1))
    fi

    local max
    max=$(grep 'READER TERM status=0 len=' "$out" 2>/dev/null | \
          sed -E 's/.*len=([0-9]+).*/\1/' | sort -n | tail -1)
    if [ "$n" -eq 64 ] && [ "$max" = 64 ]; then
        echo "PASS n=64 server getter returned len=64"
        pass=$((pass + 1))
    elif [ "$n" -gt 64 ] && { [ -z "$max" ] || [ "$max" -le 64 ]; }; then
        echo "PASS n=$n server getter never returned len>64 (max=${max:-none})"
        pass=$((pass + 1))
    else
        echo "FAIL n=$n server getter max=${max:-none}, wanted $([ "$n" -eq 64 ] && echo 64 || echo '<=64') ($out)"
        fail=$((fail + 1))
    fi
}

run_case 64 8
run_case 65 8
run_case 128 8

pgrep -f '/termlen/term_server$' | xargs -r kill 2>/dev/null
{
    echo "RESULT pass=$pass fail=$fail"
    echo "client=paramiko 5.1.0, pty-req TERM length recorded before encryption"
    echo "server=W8 term_server (verbatim wire/ssh_server6.c via recorded sed)"
} | tee evidence/clientlen/results.txt
test "$fail" -eq 0
