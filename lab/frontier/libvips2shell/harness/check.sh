#!/bin/sh
# Assertions for the libvips CVE-2026-69242 direct-call harness.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$HERE/evidence"
mkdir -p "$OUT"
PASS=0
FAIL=0
as01() { if [ "$1" -eq 1 ]; then echo 1; else echo 0; fi; }
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
            expect "$tag SANITY_SAFE=-" "$(has "$out" 'SANITY_SAFE=-')"
            if [ "$v" = vuln ]; then
                expect "$tag craft sanity accepts" "$(has "$out" 'SANITY_CRAFT=-')"
                expect "$tag chain rejects=0" "$(has "$out" 'CHAIN_REJECT=0')"
                expect "$tag bpl=-256" "$(has "$out" 'BPL=-256')"
                expect "$tag chosen 0x5a at -256" "$(has "$out" 'CHAIN SINK=5a5a5a5a00000000')"
            else
                expect "$tag craft sanity rejects" "$(has "$out" 'SANITY_CRAFT=dimension overflow')"
                expect "$tag chain skipped" "$(has "$out" 'CHAIN_SKIPPED=1')"
                expect "$tag no sink written" "$(hasnt "$out" 'CHAIN SINK=')"
            fi
            if [ "$mode" = asan ]; then
                if [ "$v" = vuln ]; then
                    expect "$tag ASan heap overflow" "$(has "$out" 'heap-buffer-overflow')"
                    expect "$tag ASan WRITE-4" "$(has "$out" 'WRITE of size 4')"
                    expect "$tag pinned write :1004" "$(has "$out" 'region.c.v8.18.2:1004')"
                    expect "$tag underflow ran" "$(has "$out" 'UNDERFLOW_RUN=1')"
                else
                    expect "$tag fixed ASan clean" "$(hasnt "$out" 'ERROR: AddressSanitizer')"
                    expect "$tag fixed underflow skipped" "$(has "$out" 'UNDERFLOW_RUN=0')"
                fi
            else
                expect "$tag no ASan report" "$(hasnt "$out" 'AddressSanitizer')"
            fi
        done
    done
done

# Compiler independence of the deterministic path.
for v in vuln fixed; do
    grep -E '^(SANITY|CHAIN|UNDERFLOW)' "$OUT/gcc-$v-plain.out" > "$OUT/norm-gcc-$v.txt"
    grep -E '^(SANITY|CHAIN|UNDERFLOW)' "$OUT/clang-$v-plain.out" > "$OUT/norm-clang-$v.txt"
    if cmp -s "$OUT/norm-gcc-$v.txt" "$OUT/norm-clang-$v.txt"; then r=1; else r=0; fi
    expect "$v gcc/clang plain traces identical" "$r"
done

# Normalized trace: PIDs, addresses, absolute paths and build ids excluded.
TRACE=$(cat "$OUT"/*.out | \
    grep -E '^(SANITY_|CHAIN|UNDERFLOW_RUN=|WRITE of size 4 at|==.*ERROR: AddressSanitizer:)' | \
    sed -E 's/0x[0-9a-fA-F]+/0xADDR/g; s/==[0-9]+==/==PID==/g' | \
    sed -E 's#(/[^ ])*/harness/#HARNESS/#g' | \
    sha256sum | cut -d' ' -f1)
printf 'PASS=%d FAIL=%d TRACE=%s\n' "$PASS" "$FAIL" "$TRACE"
[ "$FAIL" -eq 0 ]
