#!/bin/sh
# Deterministic assertions + normalized trace for libfontenc2shell.
# 50 assertions: 28 plain cases, 14 fixed ASan cases, 8 vulnerable ASan markers
# (both vulnerable exit codes are also checked). Raw reports stay in evidence/;
# only stable markers enter the trace hash (PID, addresses, paths, build ids).
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$HERE/evidence"
mkdir -p "$OUT"
PASS=0
FAIL=0

expect() { # file expected-line
    if grep -Fq "$2" "$1"; then
        PASS=$((PASS + 1))
    else
        echo "FAIL: $1 missing: $2"
        FAIL=$((FAIL + 1))
    fi
}

VULN_CASES='CASE normal ok=1 row=0 first=0 len=0 chosen=0x0000
CASE rowsize ok=1 row=128 first=1 len=1 chosen=0x0041
CASE boundary257 ok=1 row=257 first=65278 len=1 chosen=0x0041
CASE boundary256max ok=1 row=256 first=65535 len=1 chosen=0x0041
CASE oob-chosen ok=1 row=258 first=254 len=1 chosen=0x5a5a
CASE range-bug ok=1 row=4 first=0 len=0 chosen=0x0000
CASE undefine-bug ok=1 row=4 first=0 len=1 chosen=0x0041'

FIXED_CASES='CASE normal ok=1 row=0 first=0 len=0 chosen=0x0000
CASE rowsize ok=1 row=128 first=1 len=1 chosen=0x0041
CASE boundary257 ok=1 row=257 first=65278 len=1 chosen=0x0041
CASE boundary256max ok=1 row=256 first=65535 len=1 chosen=0x0041
CASE oob-chosen ok=1 row=258 first=0 len=0 chosen=0x0000
CASE range-bug ok=1 row=4 first=4 len=3 chosen=0x0043
CASE undefine-bug ok=1 row=4 first=0 len=7 chosen=0x0041'


check_cases() { # file expected-block
    printf '%s\n' "$2" > "$OUT/.expected"
    while IFS= read -r line; do
        expect "$1" "$line"
    done < "$OUT/.expected"
}
for cc in gcc clang; do
    for v in vuln fixed; do
        f="$OUT/plain-$cc-$v.out"
        ASAN_OPTIONS=detect_leaks=0 "$HERE/bin-$cc-$v-plain" > "$f" 2>&1
        if [ "$v" = vuln ]; then
            check_cases "$f" "$VULN_CASES"
        else
            check_cases "$f" "$FIXED_CASES"
        fi
    done
done

# Fixed ASan builds must complete all seven cases (negative control).
for cc in gcc clang; do
    f="$OUT/asan-$cc-fixed.out"
    ASAN_OPTIONS=detect_leaks=0 "$HERE/bin-$cc-fixed-asan" > "$f" 2>&1
    check_cases "$f" "$FIXED_CASES"
done

# Vulnerable ASan builds must abort at the pinned out-of-bounds store.
for cc in gcc clang; do
    f="$OUT/asan-$cc-vuln.out"
    rc=0
    ASAN_OPTIONS=detect_leaks=0 "$HERE/bin-$cc-vuln-asan" > "$f" 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "FAIL: $cc vuln ASan exited 0"
        FAIL=$((FAIL + 1))
    fi
    expect "$f" 'ERROR: AddressSanitizer: heap-buffer-overflow'
    expect "$f" 'WRITE of size 2'
    expect "$f" '508 bytes after 131072-byte region'
    expect "$f" 'in setCode /'
done

# Stable trace: normalize volatile fields before hashing.
{
    for t in plain-gcc-vuln plain-gcc-fixed plain-clang-vuln plain-clang-fixed \
             asan-gcc-fixed asan-clang-fixed; do
        cat "$OUT/$t.out"
    done
    for cc in gcc clang; do
        grep -E 'ERROR: AddressSanitizer|WRITE of size 2|bytes after 131072-byte region' \
            "$OUT/asan-$cc-vuln.out" || true
    done
} | sed -E \
    -e 's/==[0-9]+==/==PID==/g' \
    -e 's/0x[0-9a-f]{10,}/0xADDR/g' \
    -e 's#/[^ ]*/lab/frontier/libfontenc2shell/#LAB/#g' \
    > "$OUT/trace.txt"
TRACE=$(sha256sum "$OUT/trace.txt" | cut -d' ' -f1)
printf 'PASS=%d FAIL=%d TRACE=%s\n' "$PASS" "$FAIL" "$TRACE" > "$OUT/summary.txt"
cat "$OUT/summary.txt"
rm -f "$OUT/.expected"
[ "$FAIL" -eq 0 ]
