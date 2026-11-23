#!/bin/sh
# Deterministic assertions + normalized trace for openexr2shell.
# 52 assertions: 24 plain cases (gcc/clang x vuln/fixed x 6 lines),
# 16 fixed ASan cases (6 lines + 2 duplicate markers + 2 exit checks), and
# 12 vulnerable ASan cases (4 pre-abort lines + 4 markers per compiler).
# stable markers enter the trace hash (PID, addresses, paths, build ids).
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

VULN_PLAIN='GUARD baseline split=0 total=64 unpacked=64 rc=0
CASE baseline guard=absent total=64 b64=0xa5 b4095=0xa5
GUARD oob-chosen split=0 total=4096 unpacked=64 rc=0
CASE oob-chosen guard=absent total=4096 b64=0x5a b4095=0x5a
GUARD half-ok split=32 total=32 unpacked=32 rc=0
CASE half-ok guard=absent total=32 b64=0xa5 b4095=0xa5'

FIXED_PLAIN='GUARD baseline split=0 total=64 unpacked=64 rc=0
CASE baseline guard=absent total=64 b64=0xa5 b4095=0xa5
GUARD oob-chosen split=0 total=4096 unpacked=64 rc=23
CASE oob-chosen guard=reject rc=23 copies=0
GUARD half-ok split=32 total=32 unpacked=32 rc=0
CASE half-ok guard=absent total=32 b64=0xa5 b4095=0xa5'

FIXED_ASAN='GUARD baseline split=0 total=64 unpacked=64 rc=0
CASE baseline guard=absent total=64 copy=completed
GUARD oob-chosen split=0 total=4096 unpacked=64 rc=23
CASE oob-chosen guard=reject rc=23 copies=0
GUARD half-ok split=32 total=32 unpacked=32 rc=0
CASE half-ok guard=absent total=32 copy=completed'

check_lines() { # file expected-block
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
            check_lines "$f" "$VULN_PLAIN"
        else
            check_lines "$f" "$FIXED_PLAIN"
        fi
    done
done

# Fixed ASan builds must complete all six lines (negative control).
for cc in gcc clang; do
    f="$OUT/asan-$cc-fixed.out"
    rc=0
    ASAN_OPTIONS=detect_leaks=0 "$HERE/bin-$cc-fixed-asan" > "$f" 2>&1 || rc=$?
    expect "$f" "GUARD oob-chosen split=0 total=4096 unpacked=64 rc=23"
    expect "$f" "CASE oob-chosen guard=reject rc=23 copies=0"
    if [ "$rc" -ne 0 ]; then
        echo "FAIL: $cc fixed ASan exited $rc"
        FAIL=$((FAIL + 1))
    fi
    check_lines "$f" "$FIXED_ASAN"
done

# Vulnerable ASan builds must abort at the pinned inverse-sort memcpy.
for cc in gcc clang; do
    f="$OUT/asan-$cc-vuln.out"
    rc=0
    ASAN_OPTIONS=detect_leaks=0 "$HERE/bin-$cc-vuln-asan" > "$f" 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "FAIL: $cc vuln ASan exited 0"
        FAIL=$((FAIL + 1))
    fi
    expect "$f" 'GUARD baseline split=0 total=64 unpacked=64 rc=0'
    expect "$f" 'CASE baseline guard=absent total=64 copy=completed'
    expect "$f" 'ERROR: AddressSanitizer: heap-buffer-overflow'
    expect "$f" 'WRITE of size 4096'
    expect "$f" 'internal_zstd.c.vuln:472'
    expect "$f" '0 bytes after 64-byte region'
done

# Stable trace: normalize volatile fields before hashing.
{
    for t in plain-gcc-vuln plain-gcc-fixed plain-clang-vuln plain-clang-fixed \
             asan-gcc-fixed asan-clang-fixed; do
        cat "$OUT/$t.out"
    done
    for cc in gcc clang; do
        grep -E 'heap-buffer-overflow|WRITE of size 4096|internal_zstd.c.vuln:472|64-byte region' \
            "$OUT/asan-$cc-vuln.out" || true
    done
} | sed -E \
    -e 's/==[0-9]+==/==PID==/g' \
    -e 's/0x[0-9a-f]{6,}/0xADDR/g' \
    -e 's/BuildId: [0-9a-f]+/BuildId: ID/g' \
    -e 's#/[^ ]*/lab/frontier/openexr2shell/#LAB/#g' \
    > "$OUT/trace.txt"
TRACE=$(sha256sum "$OUT/trace.txt" | cut -d' ' -f1)
printf 'PASS=%d FAIL=%d TRACE=%s\n' "$PASS" "$FAIL" "$TRACE" > "$OUT/summary.txt"
cat "$OUT/summary.txt"
rm -f "$OUT/.expected"
[ "$FAIL" -eq 0 ]
