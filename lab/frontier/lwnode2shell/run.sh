#!/bin/sh
# Replay CVE-2026-135746 extracted harness. No network, no lwnode build.
set -u
cd "$(dirname "$0")"
PASS=0; FAIL=0
h=$(sed -n '2194,2203p' src/api-data.cc | sha256sum | cut -d' ' -f1)
hh=$(sha256sum harness.cpp | cut -d' ' -f1)
if [ "$h" = 91051bee0f65e04c42ed2ef77a8449dda7405985e9605aa7b722d445c2a520b4 ]; then
    echo "PASS pinned-loop-bytes"; PASS=$((PASS+1))
else
    echo "FAIL pinned-loop-bytes $h"; FAIL=$((FAIL+1))
fi
if [ "$hh" = d2bdb8dfa6f5f6e2ff9d18bf49537072774bf549886825b98c38605db50ff914 ]; then
    echo "PASS harness-bytes"; PASS=$((PASS+1))
else
    echo "FAIL harness-bytes $hh"; FAIL=$((FAIL+1))
fi
g++ -std=c++17 -O0 -g -fno-omit-frame-pointer -fsanitize=address harness.cpp -o asan
g++ -std=c++17 -O0 -g -fno-omit-frame-pointer harness.cpp -o plain
mkdir -p evidence
run() {
    label=$1; shift
    "$@" > "evidence/$label.txt" 2>&1
    rc=$?
    echo "rc=$rc" >> "evidence/$label.txt"
    echo "$label rc=$rc"
}
expect() {
    label=$1; file=$2; pat=$3
    if grep -Eq "$pat" "evidence/$file.txt"; then echo "PASS $label"; PASS=$((PASS+1)); else echo "FAIL $label"; FAIL=$((FAIL+1)); fi
}
run vuln-asan-attack ./asan vuln attack 48
expect vuln-asan-write1 vuln-asan-attack 'AddressSanitizer: heap-buffer-overflow'
expect vuln-asan-one-byte vuln-asan-attack 'WRITE of size 1'
expect vuln-asan-rc vuln-asan-attack 'rc=1'
run vuln-asan-safe ./asan vuln safe
expect vuln-asan-safe-clean vuln-asan-safe '^vuln safe n=8$'
run vuln-plain-attack ./plain vuln attack 48
expect vuln-chosen-byte vuln-plain-attack '^vuln attack n=9 byte8=0x48'
run vuln-plain-attack-5a ./plain vuln attack 5a
expect vuln-steered-byte vuln-plain-attack-5a '^vuln attack n=9 byte8=0x5a'
run vuln-plain-safe ./plain vuln safe
expect vuln-safe-canary vuln-plain-safe '^vuln safe n=8 byte8=0xcc'
run fixed-asan-attack ./asan fixed attack 48
expect fixed-asan-clean fixed-asan-attack '^fixed attack n=8$'
run fixed-plain-attack ./plain fixed attack 48
expect fixed-canary fixed-plain-attack '^fixed attack n=8 byte8=0xcc'
run fixed-plain-safe ./plain fixed safe
expect fixed-safe fixed-plain-safe '^fixed safe n=8 byte8=0xcc'
echo "TOTAL $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
