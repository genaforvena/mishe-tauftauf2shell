#!/bin/sh
# Deterministic assertions + normalized trace for the kicad2shell ind=-1 lane.
# Rebuilds from the shared verbatim pins, then runs baseline and low scenarios
# across g++/clang++ x vuln/fixed x plain/asan (16 invocations).
# Trace excludes PID, addresses and paths.
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

sh "$HERE/run.sh" >/dev/null
: > "$OUT/trace.txt"
for cxx in g++ clang++; do
    for v in vuln fixed; do
        for mode in plain asan; do
            B="$cxx-$v-$mode"
            for sc in baseline low; do
                F="$OUT/$B-$sc.out"
                set +e
                "$HERE/$B" "$sc" > "$F" 2>&1
                RC=$?
                set -e
                printf '%s %s rc=%d\n' "$B" "$sc" "$RC" > "$OUT/$B-$sc.rc"

                if [ "$sc" = baseline ]; then
                    expect "$F" 'rc=0 size=1 first=18288 GUARD7=11111111' "$B-baseline"
                    absent "$F" 'AddressSanitizer' "$B-baseline-asan"
                    trace "$B baseline clean"
                fi

                if [ "$sc" = low ]; then
                    if [ "$v" = vuln ] && [ "$mode" = asan ]; then
                        expect "$F" 'AddressSanitizer: heap-buffer-overflow' "$B-low-asan"
                        expect "$F" 'WRITE of size 4' "$B-low-write"
                        expect "$F" '8 bytes before 4-byte region' "$B-low-offset"
                        expect "$F" 'sch_io_altium.cpp.vuln:5919' "$B-low-site"
                        trace "$B low ASAN-WRITE4-8BEFORE-5919"
                    elif [ "$v" = vuln ] && [ "$mode" = plain ]; then
                        expect "$F" 'double free or corruption (!prev)' "$B-low-prev"
                        trace "$B low glibc-prev-inuse-corruption"
                    else
                        expect "$F" 'rc=0 size=1 first=18288 GUARD7=11111111' "$B-low-fixed-clean"
                        absent "$F" 'AddressSanitizer' "$B-low-fixed-asan"
                        if [ "$RC" -ne 0 ]; then
                            FAIL=$((FAIL+1))
                            printf 'FAIL %s: fixed rc=%d\n' "$B-low-fixed-rc" "$RC"
                        else
                            PASS=$((PASS+1))
                        fi
                        trace "$B low fixed clean"
                    fi
                fi
            done
        done
    done
done

# The corrupted 4 bytes are not an aFontSizes element: all four pinned
# consumers guard their index, and the guard allocation stays intact.
expect "$HERE/../src/sch_io_altium.cpp.vuln" \
    'if( fontId > 0 && fontId <= aFontSizes.size() )' 'consumer-2744-guard'
expect "$HERE/../src/sch_io_altium.cpp.vuln" \
    'if( aElem->FontID > 0 && aElem->FontID <= static_cast<int>( aFontSizes.size() ) )' \
    'consumer-2917-guard'
expect "$HERE/../src/sch_io_altium.cpp.vuln" \
    'if( elem.fontId > 0 && elem.fontId <= static_cast<int>( aFontSizes.size() ) )' \
    'consumers-5278-5479-guard'
trace 'four pinned consumers guarded'

sha256sum "$OUT/trace.txt" | cut -d' ' -f1 > "$OUT/trace.sha256"
printf 'PASS=%d FAIL=%d trace=%s\n' "$PASS" "$FAIL" "$(cat "$OUT/trace.sha256")"
[ "$FAIL" -eq 0 ]
