#!/bin/sh
# Deterministic assertions + normalized trace for kicad2shell.
# 24 invocations (g++/clang++ x vuln/fixed x plain/asan x baseline/attack/far)
# plus two gdb chosen-byte/guard probes. Trace excludes PID, addresses, paths.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$HERE/evidence"
mkdir -p "$OUT"
PASS=0
FAIL=0

expect() { # file expected-substring label
    if grep -qF "$2" "$1"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        printf 'FAIL %s: missing %s\n' "$3" "$2"
    fi
}
absent() { # file forbidden-substring label
    if grep -qF "$2" "$1"; then
        FAIL=$((FAIL+1))
        printf 'FAIL %s: found %s\n' "$3" "$2"
    else
        PASS=$((PASS+1))
    fi
}
trace() { printf '%s\n' "$1" >> "$OUT/trace.txt"; }

: > "$OUT/trace.txt"
for cxx in g++ clang++; do
    for v in vuln fixed; do
        for mode in plain asan; do
            B="$cxx-$v-$mode"
            for sc in baseline attack far; do
                F="$OUT/$B-$sc.out"
                set +e
                "$HERE/$B" "$sc" > "$F" 2>&1
                RC=$?
                set -e
                printf '%s %s rc=%d\n' "$B" "$sc" "$RC" > "$OUT/$B-$sc.rc"

                # baseline: valid SIZE1 only; both builds clean.
                if [ "$sc" = baseline ]; then
                    expect "$F" 'rc=0 size=1 first=72 GUARD7=11111111' "$B-baseline"
                    absent "$F" 'AddressSanitizer' "$B-baseline-asan"
                    trace "$B baseline clean"
                fi

                if [ "$sc" = attack ]; then
                    if [ "$v" = vuln ] && [ "$mode" = asan ]; then
                        expect "$F" 'AddressSanitizer: heap-buffer-overflow' "$B-attack"
                        expect "$F" 'WRITE of size 4' "$B-attack"
                        expect "$F" 'sch_io_altium.cpp.vuln:5919' "$B-attack"
                        expect "$F" '4 bytes before 4-byte region' "$B-attack"
                        trace "$B attack ASAN-WRITE4-BEFORE-5919"
                    elif [ "$v" = vuln ] && [ "$mode" = plain ]; then
                        expect "$F" 'double free or corruption' "$B-attack"
                        trace "$B attack glibc-heap-metadata-corruption"
                    else
                        expect "$F" 'rc=0 size=1 first=72 GUARD7=11111111' "$B-attack"
                        absent "$F" 'AddressSanitizer' "$B-attack-asan"
                        trace "$B attack FIXED-clean"
                    fi
                fi

                if [ "$sc" = far ]; then
                    if [ "$v" = vuln ] && [ "$mode" = asan ]; then
                        expect "$F" 'AddressSanitizer:DEADLYSIGNAL' "$B-far"
                        expect "$F" 'sch_io_altium.cpp.vuln:5919' "$B-far"
                        trace "$B far ASAN-SEGV-5919"
                    elif [ "$v" = vuln ] && [ "$mode" = plain ]; then
                        if [ "$RC" -eq 0 ]; then
                            FAIL=$((FAIL+1)); printf 'FAIL %s-far: rc=0\n' "$B"
                        else
                            PASS=$((PASS+1))
                        fi
                        trace "$B far nonzero-rc"
                    else
                        expect "$F" 'rc=0 size=0 first=-1 GUARD7=11111111' "$B-far"
                        absent "$F" 'AddressSanitizer' "$B-far-asan"
                        trace "$B far FIXED-rejected"
                    fi
                fi
            done
        done
    done
done

# gdb: chosen index, chosen 32-bit value and the four bytes actually written
# one int before the vector's heap buffer.
A="$OUT/gdb-chosen.out"
set +e
gdb -q -batch -ex 'set pagination off' \
    -ex 'break sch_io_altium.cpp.vuln:5919' -ex 'run attack' -ex 'continue' \
    -ex 'printf "IND=%d SCALED=0x%08x\n", ind, scaled' -ex 'next' \
    -ex 'x/4xb (char*)aFontSizes._M_impl._M_start-4' \
    "$HERE/g++-vuln-plain" > "$A" 2>&1
set -e
expect "$A" 'IND=0 SCALED=0x24242424' 'gdb-chosen'
expect "$A" '0x24	0x24	0x24	0x24' 'gdb-chosen-bytes'

# gdb: the fixed build reaches the new guard with the same hostile SIZE key.
B="$OUT/gdb-guard.out"
set +e
gdb -q -batch -ex 'set pagination off' \
    -ex 'break sch_io_altium.cpp.fixed:5914' -ex 'run attack' \
    -ex 'printf "FIXED_IND=%d\n", ind' -ex 'continue' \
    -ex 'printf "FIXED_IND=%d\n", ind' -ex 'continue' \
    "$HERE/g++-fixed-plain" > "$B" 2>&1
set -e
expect "$B" 'FIXED_IND=0' 'gdb-guard'
expect "$B" 'exited normally' 'gdb-guard-exit'

grep -E '^IND=|^FIXED_IND=|^0x[0-9a-f]+:' "$A" "$B" \
    | sed -E 's/^[^:]+://; s/^0x[0-9a-f]+:[[:space:]]*/OOB4: /' >> "$OUT/trace.txt"
HASH=$(sha256sum "$OUT/trace.txt" | cut -d' ' -f1)
printf 'PASS=%d FAIL=%d TRACE=%s\n' "$PASS" "$FAIL" "$HASH"
[ "$FAIL" -eq 0 ]
