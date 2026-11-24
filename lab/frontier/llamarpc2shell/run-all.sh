#!/bin/sh
# Replay the CVE-2026-118375 lab checks. Deterministic, loopback-only.
set -u
cd "$(dirname "$0")"
PASS=0
FAIL=0
run() {
    label=$1; shift
    out="evidence/$label.txt"
    mkdir -p evidence
    "$@" > "$out" 2>&1
    rc=$?
    echo "$label rc=$rc" >> "$out"
    echo "$label rc=$rc"
}
expect() {
    label=$1; file=$2; pattern=$3
    if grep -Eq "$pattern" "evidence/$file.txt"; then
        echo "PASS $label"; PASS=$((PASS+1))
    else
        echo "FAIL $label (missing /$pattern/ in evidence/$file.txt)"; FAIL=$((FAIL+1))
    fi
}
expect_rc() {
    label=$1; file=$2; want=$3
    got=$(grep -o 'rc=[0-9]*' "evidence/$file.txt" | head -1)
    if [ "$got" = "rc=$want" ]; then
        echo "PASS $label"; PASS=$((PASS+1))
    else
        echo "FAIL $label (want rc=$want, got $got)"; FAIL=$((FAIL+1))
    fi
}

run vuln-asan-attack ./vuln-asan attack
expect_rc vuln-asan-attack-rc vuln-asan-attack 1
expect vuln-asan-stack-overflow vuln-asan-attack 'AddressSanitizer: stack-buffer-overflow'
expect vuln-asan-write64 vuln-asan-attack 'WRITE of size 64'
expect vuln-asan-frame vuln-asan-attack 'socket_t::impl::rdma_recv.*transport.cpp:520'

run vuln-asan-safe ./vuln-asan safe
expect_rc vuln-asan-safe-rc vuln-asan-safe 0
expect vuln-asan-safe-clean vuln-asan-safe 'recv_data=1 cmd=0x41 after0=0xcc'

run vuln-plain-attack ./vuln-plain attack
expect vuln-plain-chosen vuln-plain-attack 'cmd=0x41 after0=0x42 after1=0x43 after7=0x49'

run vuln-plain-safe ./vuln-plain safe
expect vuln-plain-safe-clean vuln-plain-safe 'recv_data=1 cmd=0x41 after0=0xcc'

run fixed-asan-attack ./fixed-asan attack
expect_rc fixed-asan-attack-rc fixed-asan-attack 0
expect fixed-asan-rejects fixed-asan-attack 'recv_data=0 cmd=0x00 after0=0xcc'
expect fixed-asan-no-asan fixed-asan-attack '^transport=RDMA byte_len=64$'

run fixed-asan-safe ./fixed-asan safe
expect fixed-asan-safe-ok fixed-asan-safe 'recv_data=1 cmd=0x41 after0=0xcc'

run fixed-plain-attack ./fixed-plain attack
expect fixed-plain-rejects fixed-plain-attack 'recv_data=0 cmd=0x00 after0=0xcc'

run fixed-plain-safe ./fixed-plain safe
expect fixed-plain-safe-ok fixed-plain-safe 'recv_data=1 cmd=0x41 after0=0xcc'

run steer-vuln-48 ./vuln-plain attack 48
expect steer-vuln-48-bytes steer-vuln-48 'cmd=0x48 after0=0x48 after1=0x48 after7=0x48'

run steer-fixed-48 ./fixed-plain attack 48
expect steer-fixed-48-canary steer-fixed-48 'recv_data=0 cmd=0x00 after0=0xcc'

run steer-vuln-5a ./vuln-plain attack 5a
expect steer-vuln-5a-bytes steer-vuln-5a 'cmd=0x5a after0=0x5a after1=0x5a after7=0x5a'

echo "TOTAL $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
