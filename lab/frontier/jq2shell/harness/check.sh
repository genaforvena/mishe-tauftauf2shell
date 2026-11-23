#!/bin/sh
# Assertions for the jq CVE-2026-32316 direct-call harness.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$HERE/evidence"
mkdir -p "$OUT"
PASS=0
FAIL=0
expect() { if [ "$2" -eq 1 ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); echo "FAIL: $1"; fi; }
has() { grep -qF -- "$2" "$1" && echo 1 || echo 0; }
hasnt() { grep -qF -- "$2" "$1" && echo 0 || echo 1; }
iszero() { if [ "$1" -eq 0 ]; then echo 1; else echo 0; fi; }
notzero() { if [ "$1" -ne 0 ]; then echo 1; else echo 0; fi; }

for cc in gcc clang; do
    for v in vuln fixed; do
        for mode in plain asan; do
            bin="$HERE/bin-$cc-$v-$mode"
            out="$OUT/$cc-$v-$mode.out"
            "$bin" > "$out" 2>&1
            rc=$?
            tag="$cc-$v-$mode"
            if [ "$mode" = plain ] || [ "$v" = fixed ]; then
                expect "$tag rc=0 (rc=$rc)" "$(iszero "$rc")"
            else
                expect "$tag rc!=0 (rc=$rc)" "$(notzero "$rc")"
            fi
            expect "$tag geometry LEN/REM" "$(has "$out" 'DBG LEN=2147483646 ALLOC=2147483647 REM=1 COUNT=1')"
            if [ "$v" = vuln ]; then
                if [ "$mode" = plain ]; then
                    expect "$tag append ALLOC=32 REQ=2^31-2/2" "$(has "$out" 'APPEND ALLOC=32 REQ1=2147483646 REQ2=2 KIND=5')"
                    expect "$tag append chosen bytes past allocation" "$(has "$out" 'APPEND SINK=5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a')"
                    expect "$tag bad ALLOC=6" "$(has "$out" 'BAD ALLOC=6 U8CALLS=16 KIND=5')"
                    expect "$tag bad chosen bytes past allocation" "$(has "$out" 'BAD SINK=5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a')"
                else
                    expect "$tag ASan heap overflow" "$(has "$out" 'ERROR: AddressSanitizer: heap-buffer-overflow')"
                    expect "$tag ASan WRITE-48" "$(has "$out" 'WRITE of size 48')"
                    expect "$tag pinned append memcpy :1191" "$(has "$out" 'jv.c.vuln:1191')"
                    expect "$tag no bad report in default run" "$(hasnt "$out" 'BAD ALLOC=')"
                fi
            else
                expect "$tag append guard rejects" "$(has "$out" 'APPEND REJECT=1')"
                expect "$tag bad guard rejects" "$(has "$out" 'BAD REJECT=1')"
                expect "$tag fixed no sink" "$(hasnt "$out" 'SINK=')"
                if [ "$mode" = asan ]; then
                    expect "$tag fixed ASan clean" "$(hasnt "$out" 'ERROR: AddressSanitizer')"
                fi
            fi
        done
    done
done

# Second bug needs an isolated ASan run: the default run aborts inside append.
for cc in gcc clang; do
    for v in vuln fixed; do
        out="$OUT/$cc-$v-bad-asan.out"
        "$HERE/bin-$cc-$v-asan" bad > "$out" 2>&1
        rc=$?
        tag="$cc-$v-bad-asan"
        if [ "$v" = vuln ]; then
            expect "$tag rc!=0 (rc=$rc)" "$(notzero "$rc")"
            expect "$tag ASan heap overflow" "$(has "$out" 'ERROR: AddressSanitizer: heap-buffer-overflow')"
            expect "$tag ASan WRITE-3" "$(has "$out" 'WRITE of size 3')"
            expect "$tag pinned bad write :1126" "$(has "$out" 'jv.c.vuln:1126')"
            expect "$tag ASan 23-byte region (6-byte string)" "$(has "$out" '23-byte region')"
        else
            expect "$tag rc=0 (rc=$rc)" "$(iszero "$rc")"
            expect "$tag fixed bad guard" "$(has "$out" 'BAD REJECT=1')"
            expect "$tag fixed ASan clean" "$(hasnt "$out" 'ERROR: AddressSanitizer')"
        fi
    done
done

for v in vuln fixed; do
    grep -E '^(DBG|APPEND|BAD)' "$OUT/gcc-$v-plain.out" > "$OUT/norm-gcc-$v.txt"
    grep -E '^(DBG|APPEND|BAD)' "$OUT/clang-$v-plain.out" > "$OUT/norm-clang-$v.txt"
    if cmp -s "$OUT/norm-gcc-$v.txt" "$OUT/norm-clang-$v.txt"; then r=1; else r=0; fi
    expect "$v gcc/clang plain traces identical" "$r"
done

# Normalized trace: PIDs, addresses, absolute paths and build ids excluded.
TRACE=$(cat "$OUT"/*.out | \
    grep -E '^(DBG|APPEND|BAD|WRITE of size (48|3) at|==.*ERROR: AddressSanitizer:)' | \
    sed -E 's/0x[0-9a-fA-F]+/0xADDR/g; s/==[0-9]+==/==PID==/g' | \
    sed -E 's#(/[^ ])*/harness/#HARNESS/#' | \
    sha256sum | cut -d' ' -f1)
printf 'PASS=%d FAIL=%d TRACE=%s\n' "$PASS" "$FAIL" "$TRACE"
[ "$FAIL" -eq 0 ]
