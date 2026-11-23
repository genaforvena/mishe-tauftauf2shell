#!/bin/sh
# Replay and check the real-compound-file reachability lane.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
mkdir -p evidence
sh run.sh >/dev/null

PASS=0
FAIL=0
trace=""

check() { # description command...
    desc=$1; shift
    if "$@" >/dev/null 2>&1; then
        PASS=$((PASS+1)); trace="$trace
PASS $desc"
    else
        FAIL=$((FAIL+1)); trace="$trace
FAIL $desc"
    fi
}

for cxx in g++ clang++; do
    for v in vuln fixed; do
        for mode in asan plain; do
            for sc in baseline attackz attackneg attackfar; do
                b="$cxx-$v-$mode-$sc"
                set +e
                ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 \
                    "./$cxx-$v-$mode" "fixtures/FileHeader-$sc.SchLib" \
                    > "evidence/$b.out" 2>&1
                rc=$?
                set -e
                printf '%s\n' "$rc" > "evidence/$b.rc"
                trace="$trace
RUN $b rc=$rc"
            done
        done
    done
done

check "olefile verifies all four CFB fixtures" \
    grep -q ALL_FIXTURES_OK evidence/olefile-verify.out
check "all upstream and ParseLibHeader pins verify" \
    sh -c "grep -q 'sch_io_altium.cpp.vuln.slice: OK' evidence/pins-verify.out && grep -q 'altium_binary_parser.cpp.readprops.slice: OK' evidence/pins-verify.out"

for cxx in g++ clang++; do
    check "$cxx real CFB read extracted the FileHeader stream" \
        grep -q 'stream=107' "evidence/$cxx-vuln-asan-attackz.out"
    check "$cxx real parser preserves SIZEZ from CFB stream" \
        grep -q 'real-key: SIZEZ=84215045' "evidence/$cxx-vuln-asan-attackz.out"
    check "$cxx vulnerable ASan attackz: WRITE of size 4" \
        grep -q 'WRITE of size 4' "evidence/$cxx-vuln-asan-attackz.out"
    check "$cxx vulnerable ASan top frame at pinned :5919" \
        grep -q 'sch_io_altium.cpp.vuln:5919' "evidence/$cxx-vuln-asan-attackz.out"
    check "$cxx vulnerable ASan allocation from resize at :5915" \
        grep -q 'sch_io_altium.cpp.vuln:5915' "evidence/$cxx-vuln-asan-attackz.out"
    check "$cxx vulnerable plain attackz aborts on heap corruption" \
        grep -q 'double free or corruption' "evidence/$cxx-vuln-plain-attackz.out"
    check "$cxx vulnerable attackneg SEGV observed" \
        sh -c "grep -qE 'SEGV|Segmentation fault' 'evidence/$cxx-vuln-asan-attackneg.out' 'evidence/$cxx-vuln-plain-attackneg.out'"
    check "$cxx vulnerable ASan attackfar writes 8 bytes before region" \
        grep -q '8 bytes before 4-byte region' "evidence/$cxx-vuln-asan-attackfar.out"
    check "$cxx vulnerable baseline has no ASan report" \
        sh -c "! grep -q 'ERROR: AddressSanitizer' 'evidence/$cxx-vuln-asan-baseline.out'"
    for sc in baseline attackz attackneg attackfar; do
        for mode in asan plain; do
            check "$cxx fixed $mode $sc clean" \
                sh -c "grep -q 'rc=0 size=1 first=72 GUARD7=11111111' 'evidence/$cxx-fixed-$mode-$sc.out'"
        done
    done
    check "$cxx fixed attackz has no ASan report" \
        sh -c "! grep -q 'ERROR: AddressSanitizer' 'evidence/$cxx-fixed-asan-attackz.out'"
done

printf '%s\n' "$trace" > evidence/trace-realcfb.txt
printf 'PASS=%s FAIL=%s\n' "$PASS" "$FAIL" | tee -a evidence/trace-realcfb.txt
sha256sum evidence/trace-realcfb.txt | tee evidence/trace-realcfb.sha256
[ "$FAIL" -eq 0 ]
