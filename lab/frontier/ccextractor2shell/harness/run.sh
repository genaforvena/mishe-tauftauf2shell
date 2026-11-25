#!/bin/sh
# Reproduce all ccextractor2shell harness checks from this directory.
set -eu
cd "$(dirname "$0")"
mkdir -p evidence

gcc -O1 -g -fsanitize=address -DASAN_BUILD -o vuln-asan harness.c
clang -O1 -g -fsanitize=address -DASAN_BUILD -o vuln-asan-clang harness.c
clang -O1 -g -fno-builtin-memcpy -fsanitize=address -DASAN_BUILD -o vuln-asan-clang-nobuiltin harness.c
gcc -O1 -g -o vuln-plain harness.c
gcc -O1 -g -DFIXED_BUILD -DASAN_BUILD -o fixed-asan harness.c
gcc -O1 -g -DFIXED_BUILD -o fixed-plain harness.c

pass=0
fail=0
check() {
    label=$1
    shift
    if "$@"; then
        echo "PASS $label"
        pass=$((pass + 1))
    else
        echo "FAIL $label"
        fail=$((fail + 1))
    fi
}

# Vulnerable build: ASan must report an OOB WRITE through the pinned function.
./vuln-asan attack > evidence/vuln-asan.out 2>&1 && rc=0 || rc=$?
check "gcc ASan attack faults" test "$rc" -ne 0
check "gcc ASan reports heap-buffer-overflow" grep -q 'heap-buffer-overflow' evidence/vuln-asan.out
check "gcc ASan reports WRITE of derived length" grep -q 'WRITE of size 2101248' evidence/vuln-asan.out
check "gcc ASan reports 0 bytes after region" grep -q '0 bytes after 2097272-byte region' evidence/vuln-asan.out
check "gcc ASan stack names pinned function" grep -q 'parse_mpeg_packet.inc:10' evidence/vuln-asan.out
check "gcc ASan safe mode clean" ./vuln-asan safe

# Clang default build is a preserved negative; -fno-builtin-memcpy reports.
./vuln-asan-clang attack > evidence/vuln-asan-clang.out 2>&1 && rc=0 || rc=$?
check "clang default ASan negative preserved" test "$rc" -eq 0
./vuln-asan-clang-nobuiltin attack > evidence/vuln-asan-clang-nobuiltin.out 2>&1 && rc=0 || rc=$?
check "clang no-builtin ASan attack faults" test "$rc" -ne 0
check "clang no-builtin ASan reports WRITE" grep -q 'WRITE of size 2101248' evidence/vuln-asan-clang-nobuiltin.out
check "clang safe mode clean" ./vuln-asan-clang-nobuiltin safe

# Plain build: chosen bytes readable past nominal BUFSIZE.
./vuln-plain attack > evidence/vuln-plain-attack.out 2>&1
check "plain attack rc 0" test "$?" -eq 0
check "chosen bytes at BUFSIZE" grep -q 'canary_at_BUFSIZE=5348452d434345584d495348452d4343' evidence/vuln-plain-attack.out
check "chosen bytes match expected" grep -q 'expected=5348452d434345584d495348452d4343' evidence/vuln-plain-attack.out
check "plain safe mode clean" ./vuln-plain safe

# Local guard fix: attack rejected, no chosen bytes written.
check "fixed ASan attack clean" ./fixed-asan attack
./fixed-plain attack > evidence/fixed-plain-attack.out 2>&1
check "fixed plain attack returns EOF" grep -q 'ret=1 past=0' evidence/fixed-plain-attack.out
check "fixed plain leaves nominal boundary clean" grep -q 'canary_at_BUFSIZE=00000000000000000000000000000000' evidence/fixed-plain-attack.out

echo "PASS=$pass FAIL=$fail"
test "$fail" -eq 0
