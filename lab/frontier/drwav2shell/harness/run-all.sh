#!/bin/sh
# Reproduce the dr_wav 0.14.5 smpl/cue metadataCursor desync, with a 0.14.6 control.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p evidence

gcc -O0 -g -fsanitize=address -I ../pins/vuln -o vuln-asan harness.c || exit 1
gcc -O0 -g -I ../pins/vuln -o vuln-plain harness.c || exit 1
gcc -O0 -g -fsanitize=address -I ../pins/fixed -o fixed-asan harness.c || exit 1
gcc -O0 -g -I ../pins/fixed -o fixed-plain harness.c || exit 1
if command -v clang >/dev/null 2>&1; then
    clang -O0 -g -fsanitize=address -I ../pins/vuln -o vuln-asan-clang harness.c || exit 1
fi
pass=0
fail=0
run() {
    n=$1; b=$2; m=$3
    { "$b" "$m"; echo "rc=$?"; } >"evidence/$n.out" 2>&1
}
expect() {
    if grep -q -- "$3" "evidence/$2.out"; then pass=$((pass + 1)); echo "PASS $1";
    else fail=$((fail + 1)); echo "FAIL $1"; fi
}
expect_not() {
    if grep -q -- "$3" "evidence/$2.out"; then fail=$((fail + 1)); echo "FAIL $1";
    else pass=$((pass + 1)); echo "PASS $1"; fi
}

run vuln-asan-chosen ./vuln-asan chosen
run vuln-asan-bad ./vuln-asan bad
run vuln-asan-safe ./vuln-asan safe
run fixed-asan-chosen ./fixed-asan chosen
run fixed-asan-bad ./fixed-asan bad
run fixed-asan-safe ./fixed-asan safe
run vuln-plain-chosen ./vuln-plain chosen
run vuln-plain-bad ./vuln-plain bad
run vuln-plain-safe ./vuln-plain safe
run fixed-plain-chosen ./fixed-plain chosen
run fixed-plain-bad ./fixed-plain bad
if [ -x ./vuln-asan-clang ]; then
    run vuln-asan-clang-chosen ./vuln-asan-clang chosen
    run vuln-asan-clang-bad ./vuln-asan-clang bad
fi

expect 'vuln header is 0.14.5' vuln-asan-chosen 'DRWAV_VERSION_STRING=0.14.5'
expect 'fixed header is 0.14.6' fixed-asan-chosen 'DRWAV_VERSION_STRING=0.14.6'
expect 'vuln ASan chosen write completes' vuln-asan-chosen 'rc=0'
expect 'vuln ASan metadata count desync' vuln-asan-chosen 'init=OK metadataCount=1'
expect 'vuln ASan CHOSEN_WORD_PRESENT' vuln-asan-chosen 'CHOSEN_WORD_PRESENT=1'
expect 'vuln ASan bad pointer faults on WRITE' vuln-asan-bad 'The signal is caused by a WRITE memory access'
expect 'vuln ASan bad pointer fault address from file low bits' vuln-asan-bad '0x50f041414155'
expect 'vuln ASan chosen bytes at chosen destination' vuln-asan-chosen 'target_after=.*4b434148'
expect 'vuln ASan bad pointer nonzero exit' vuln-asan-bad 'rc=1'
expect 'vuln ASan safe control clean' vuln-asan-safe 'rc=0'
expect_not 'vuln ASan safe control no sanitizer error' vuln-asan-safe 'ERROR: AddressSanitizer'
expect_not 'vuln ASan safe control no chosen word' vuln-asan-safe 'CHOSEN_WORD_PRESENT=1'
expect 'fixed ASan chosen clean' fixed-asan-chosen 'rc=0'
expect_not 'fixed ASan chosen no sanitizer error' fixed-asan-chosen 'ERROR: AddressSanitizer'
expect_not 'fixed ASan chosen no chosen word' fixed-asan-chosen 'CHOSEN_WORD_PRESENT=1'
expect 'fixed ASan bad-pointer control clean' fixed-asan-bad 'rc=0'
expect_not 'fixed ASan bad-pointer no sanitizer error' fixed-asan-bad 'ERROR: AddressSanitizer'
expect 'fixed ASan safe control clean' fixed-asan-safe 'rc=0'
expect 'vuln plain chosen word present' vuln-plain-chosen 'CHOSEN_WORD_PRESENT=1'
expect 'vuln plain chosen bytes' vuln-plain-chosen '4b43414842424242'
expect_not 'vuln plain safe no chosen word' vuln-plain-safe 'CHOSEN_WORD_PRESENT=1'
expect 'fixed plain chosen no chosen word' fixed-plain-chosen 'CHOSEN_WORD_PRESENT=0'
expect 'fixed plain bad-pointer control clean' fixed-plain-bad 'rc=0'
if [ -x ./vuln-asan-clang ]; then
    expect 'clang ASan chosen word present' vuln-asan-clang-chosen 'CHOSEN_WORD_PRESENT=1'
    expect 'clang ASan bad pointer WRITE fault' vuln-asan-clang-bad 'The signal is caused by a WRITE memory access'
fi

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
