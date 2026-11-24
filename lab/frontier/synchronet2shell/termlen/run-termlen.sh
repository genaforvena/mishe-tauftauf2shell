#!/usr/bin/env bash
# W8 bounded probe: does the real vendored cryptlib pty-req parser cap TERM at
# CRYPT_MAX_TEXTSIZE=64? Pinned source: session/ssh2_msgsvr.c:661 calls
# readString32(stream, stringBuffer, CRYPT_MAX_TEXTSIZE, &stringLength) with
# stringBuffer[CRYPT_MAX_TEXTSIZE+8] (line 564); enc_dec/misc_rw.c:332-334
# rejects length > dataMaxLength with CRYPT_ERROR_BADDATA (no truncation).
# The server source is the verbatim W3 wire probe with only the port and the
# getter probe buffer enlarged, both by build-time sed recorded below.
# All traffic is loopback only; no external system is contacted.
set -uo pipefail
cd "$(dirname "$0")"
ROOT=../src-tree/3rdp/src/cl
LIB=$ROOT/libcl.a
test -f "$LIB" && test -f "$ROOT/cryptlib.h" || { echo "MISSING_CRYPTLIB"; exit 2; }

sed -e 's/#define PORT 22222/#define PORT 22227/' \
    -e 's/char probe\[128\]/char probe[4096]/' \
    ../wire/ssh_server6.c > term_server.c
gcc -g -O0 -I"$ROOT" term_server.c "$LIB" -lpthread -o term_server || exit 3

mkdir -p evidence
{
    echo "probe: verbatim ../wire/ssh_server6.c via recorded build-time sed"
    echo "sed: -e s/#define PORT 22222/#define PORT 22227/ -e s/char probe[128]/char probe[4096]/"
    sha256sum ../wire/ssh_server6.c term_server.c "$LIB" \
        "$ROOT/session/ssh2_msgsvr.c" "$ROOT/enc_dec/misc_rw.c" \
        "$ROOT/misc/consts.h" "$ROOT/cryptlib.h"
} > evidence/provenance.txt

pass=0
fail=0
run_case() {
    local term_len=$1 out=$2 seconds=$3
    local term pid
    pgrep -f '/term_server$' | xargs -r kill 2>/dev/null
    : > "$out"
    term=$(python3 -c "print('T' * $term_len, end='')")
    ./term_server > "$out" 2>&1 &
    pid=$!
    sleep 1
    (for i in $(seq 1 $((seconds / 2))); do echo x; sleep 0.2; done) | \
      TERM="$term" timeout $((seconds + 4)) ssh -tt \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=none -o PubkeyAuthentication=no \
        -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
        -o HostKeyAlgorithms=+ssh-rsa -o ConnectTimeout=5 \
        -p 22227 lab@127.0.0.1 'cat' > "${out%.out}-client.log" 2>&1
    wait "$pid" 2>/dev/null
}

# Report the maximum TERM length the getter actually returned for a case.
max_len() {
    grep 'READER TERM status=0 len=' "$1" 2>/dev/null | \
      sed -E 's/.*len=([0-9]+).*/\1/' | sort -n | tail -1
}

expect_exact() {
    local out=$1 want=$2 label=$3 got
    got=$(max_len "$out")
    if [ "$got" = "$want" ]; then
        echo "PASS $label (max getter len=$got)"
        pass=$((pass + 1))
    else
        echo "FAIL $label (want max getter len=$want, got '${got:-none}'; $out)"
        fail=$((fail + 1))
    fi
}

expect_capped() {
    local out=$1 label=$2 got
    got=$(max_len "$out")
    if [ -z "$got" ] || [ "$got" -le 64 ]; then
        echo "PASS $label (max getter len=${got:-none}, never >64)"
        pass=$((pass + 1))
    else
        echo "FAIL $label (max getter len=$got exceeds 64; $out)"
        fail=$((fail + 1))
    fi
}

run_case 40 evidence/term40.out 6
expect_exact evidence/term40.out 40 'TERM=40 control: getter len=40'

run_case 64 evidence/term64.out 8
expect_exact evidence/term64.out 64 'TERM=64 baseline: getter len=64'

for n in 65 128 256; do
    run_case "$n" "evidence/term${n}.out" 8
    expect_capped "evidence/term${n}.out" "TERM=${n}: no getter len >64"
done

pgrep -f '/term_server$' | xargs -r kill 2>/dev/null
echo "RESULT pass=$pass fail=$fail"
echo "$pass" > evidence/pass.txt
echo "$fail" > evidence/fail.txt
test "$fail" -eq 0
