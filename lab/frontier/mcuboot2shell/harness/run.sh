#!/bin/sh
# Reproduce the pinned MCUboot decrypt_region_inplace() write-window bug.
# Expected: vulnerable function OOB-writes under ASan; upstream fix is clean.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p evidence

build() { "$@" || exit 1; }
build gcc -O1 -g -fsanitize=address -DASAN_BUILD -o vuln-asan harness.c
build gcc -O1 -g -fno-stack-protector -o vuln-plain harness.c
build gcc -O1 -g -DFIXED_BUILD -DASAN_BUILD -o fixed-asan harness.c
build gcc -O1 -g -DFIXED_BUILD -fno-stack-protector -o fixed-plain harness.c
if command -v clang >/dev/null 2>&1; then
    build clang -O1 -g -fsanitize=address -DASAN_BUILD -o vuln-asan-clang harness.c
fi

pass=0
fail=0
run() {
    # run <evidence-name> <binary> <mode> [chosen-string]
    n=$1; b=$2; m=$3; s=${4:-MISHE-MCUBOOT!!}
    "$b" "$m" "$s" >"evidence/$n.out" 2>&1
    echo "$?" >"evidence/$n.rc"
}
expect() {
    # expect <description> <evidence-name> <grep-pattern>
    if grep -q -- "$3" "evidence/$2.out"; then
        pass=$((pass + 1)); echo "PASS $1"
    else
        fail=$((fail + 1)); echo "FAIL $1"
    fi
}
expect_not() {
    if grep -q -- "$3" "evidence/$2.out"; then
        fail=$((fail + 1)); echo "FAIL $1"
    else
        pass=$((pass + 1)); echo "PASS $1"
    fi
}

run vuln-asan-edge ./vuln-asan edge
run vuln-asan-attack ./vuln-asan attack
run vuln-asan-attack2 ./vuln-asan attack2
run vuln-asan-safe ./vuln-asan safe
run fixed-asan-edge ./fixed-asan edge
run fixed-asan-attack ./fixed-asan attack
run fixed-asan-attack2 ./fixed-asan attack2
run vuln-plain-edge ./vuln-plain edge
run vuln-plain-attack ./vuln-plain attack
run vuln-plain-attack2 ./vuln-plain attack2
run vuln-plain-safe ./vuln-plain safe
run fixed-plain-edge ./fixed-plain edge
run fixed-plain-attack ./fixed-plain attack
run fixed-plain-attack2 ./fixed-plain attack2
run vuln-plain-chosen ./vuln-plain attack 'ABCD-MCUBOOT-XYZ'


expect 'vuln ASan edge-mode dynamic stack overflow' vuln-asan-edge 'dynamic-stack-buffer-overflow'
expect 'vuln ASan edge-mode WRITE at poisoned byte' vuln-asan-edge 'WRITE of size 1'
expect 'vuln ASan safe control clean' vuln-asan-safe 'rc=0 mode=safe'
expect_not 'vuln ASan safe has no sanitizer error' vuln-asan-safe 'ERROR: AddressSanitizer'
expect 'fixed ASan edge-mode clean' fixed-asan-edge 'rc=0 mode=edge'
expect_not 'fixed ASan edge-mode no sanitizer error' fixed-asan-edge 'ERROR: AddressSanitizer'

expect 'fixed ASan second-sector clean' fixed-asan-attack 'rc=0 mode=attack'
expect_not 'fixed ASan second-sector no sanitizer error' fixed-asan-attack 'ERROR: AddressSanitizer'
expect 'fixed ASan TLV-clamp clean' fixed-asan-attack2 'rc=0 mode=attack2'
expect_not 'fixed ASan TLV-clamp no sanitizer error' fixed-asan-attack2 'ERROR: AddressSanitizer'
expect 'vuln plain chosen bytes at OOB destination' vuln-plain-attack '4d495348452d4d4355424f4f542121'
expect 'vuln plain deep destination buf+6144' vuln-plain-attack 'dst=buf+6144'
expect 'vuln plain TLV-clamp destination buf+1024' vuln-plain-attack2 'dst=buf+1024'
expect 'vuln plain TLV-clamp length 3000' vuln-plain-attack2 'decrypt_len=3000'
expect 'vuln plain safe destination buf+0' vuln-plain-safe 'dst=buf+0'
expect 'fixed plain edge destination buf+8' fixed-plain-edge 'dst=buf+8'
expect 'fixed plain deep destination buf+2048' fixed-plain-attack 'dst=buf+2048'
expect 'fixed plain TLV-clamp destination buf+1024' fixed-plain-attack2 'dst=buf+1024'
expect 'fixed plain TLV-clamp length 1976' fixed-plain-attack2 'decrypt_len=1976'
expect 'caller-chosen bytes flow to OOB destination' vuln-plain-chosen '414243442d4d4355424f4f542d58595a'

if command -v valgrind >/dev/null 2>&1; then
    valgrind --error-exitcode=99 ./vuln-plain attack >evidence/vuln-valgrind-attack.out 2>&1
    expect 'valgrind sees invalid write past VLA' vuln-valgrind-attack 'Invalid write of size 1'
fi


if [ -x ./vuln-asan-clang ]; then
    run vuln-asan-clang-edge ./vuln-asan-clang edge
    expect 'clang ASan agrees on overflow' vuln-asan-clang-edge 'buffer-overflow'
fi

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
