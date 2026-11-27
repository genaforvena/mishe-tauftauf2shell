#!/bin/sh
# Replay the CVE-2026-40489 lab checks from pinned, offline sources.
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
        PASS=$((PASS + 1))
        echo "PASS $name"
    else
        FAIL=$((FAIL + 1))
        echo "FAIL $name"
    fi
}
check_absent() {
    name=$1
    file=$2
    shift 2
    if grep -q -- "$1" "$file"; then
        FAIL=$((FAIL + 1))
        echo "FAIL $name"
    else
        PASS=$((PASS + 1))
        echo "PASS $name"
    fi
}
run() {
    label=$1
    shift
    "$@" > "evidence/$label.out" 2>&1
    echo "$?" > "evidence/$label.rc"
}

echo "PIN_CHECK"
sha256sum -c SHA256SUMS > runs/pins.out 2>&1 || { cat runs/pins.out; exit 2; }
echo "PINS_OK $(grep -c ': OK$' runs/pins.out)"

sh build-real.sh > runs/build.out 2>&1 || { tail -30 runs/build.out; exit 3; }
check BUILD_VULN_ASAN runs/build.out 'BUILD_OK vuln-asan'
check BUILD_FIXED_ASAN runs/build.out 'BUILD_OK fixed-asan'
check BUILD_VULN_PLAIN runs/build.out 'BUILD_OK vuln-plain'
check BUILD_FIXED_PLAIN runs/build.out 'BUILD_OK fixed-plain'

V=work/ecglob-vuln-asan
F=work/ecglob-fixed-asan
VP=work/ecglob-vuln-plain
FP=work/ecglob-fixed-plain

run direct-asan-8192 "$V" direct 8192 B
check D_SAFE_8192 evidence/direct-asan-8192.out 'DIRECT n=8192 byte=42 rc=-1'
check_absent D_SAFE_8192_CLEAN evidence/direct-asan-8192.out 'AddressSanitizer'

run direct-asan-8193 "$V" direct 8193 B
check D_SAFE_8193 evidence/direct-asan-8193.out 'DIRECT n=8193 byte=42 rc=-1'
check_absent D_SAFE_8193_CLEAN evidence/direct-asan-8193.out 'AddressSanitizer'

run direct-asan-8194 "$V" direct 8194 C
check D_EDGE_8194 evidence/direct-asan-8194.out 'WRITE of size 8195'
check D_EDGE_SINK evidence/direct-asan-8194.out 'ec_glob.c:100'

run direct-asan-8200 "$V" direct 8200 C
check D_ASAN_8200 evidence/direct-asan-8200.out 'WRITE of size 8201'
check D_ASAN_SINK evidence/direct-asan-8200.out 'ec_glob.c:100'
check D_ASAN_LPATTERN evidence/direct-asan-8200.out "'l_pattern'"

run direct-fixed-asan-8200 "$F" direct 8200 C
check D_FIXED_8200 evidence/direct-fixed-asan-8200.out 'DIRECT n=8200 byte=43 rc=-1'
check_absent D_FIXED_8200_CLEAN evidence/direct-fixed-asan-8200.out 'AddressSanitizer'

python3 harness/make-case.py "$ROOT/work/case-attack" 4096 > runs/case-attack.txt
python3 harness/make-case.py "$ROOT/work/case-safe" 64 > runs/case-safe.txt
ATTACK=$(tail -1 runs/case-attack.txt)
SAFE=$(tail -1 runs/case-safe.txt)

run file-asan-attack "$V" file "$ATTACK"
check F_ASAN_ATTACK evidence/file-asan-attack.out 'stack-buffer-overflow'
check F_ASAN_SIZE evidence/file-asan-attack.out 'WRITE of size 1021'
check F_ASAN_REALCALLER evidence/file-asan-attack.out 'editorconfig.c:268'
check F_ASAN_PARSE evidence/file-asan-attack.out 'editorconfig_parse'

run file-asan-safe "$V" file "$SAFE"
check F_SAFE evidence/file-asan-safe.out 'FILE rc=0'
check_absent F_SAFE_CLEAN evidence/file-asan-safe.out 'AddressSanitizer'

run file-fixed-asan-attack "$F" file "$ATTACK"
check F_FIXED evidence/file-fixed-asan-attack.out 'FILE rc=0'
check_absent F_FIXED_CLEAN evidence/file-fixed-asan-attack.out 'AddressSanitizer'

run file-plain-attack "$VP" file "$ATTACK"
check F_PLAIN_SURVIVES evidence/file-plain-attack.out 'FILE rc=0'

run file-fixed-plain-attack "$FP" file "$ATTACK"
check F_PLAIN_FIXED evidence/file-fixed-plain-attack.rc '0'
gdb -q -batch -ex 'break ec_glob.c:101' -ex 'run' -ex 'x/32bx l_pattern+8188' -ex 'info frame' --args "$VP" direct 8200 C > evidence/gdb-chosen.out 2>&1
check GDB_CHOSEN evidence/gdb-chosen.out '0x43'
check GDB_FRAME evidence/gdb-chosen.out 'saved rip'

printf 'RUN_ALL_OK %s PASS / %s FAIL\n' "$PASS" "$FAIL" | tee runs/summary.txt
sha256sum runs/summary.txt | tee runs/summary.sha256
[ "$FAIL" -eq 0 ]
