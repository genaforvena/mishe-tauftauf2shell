#!/usr/bin/env bash
# External-caller probe: Debian speex 1.2.1-4 ships an autopkgtest
# (debian/tests/bits-boundary.c) that calls speex_bits_read_whole_bytes on a
# non-owner, already-buffered SpeexBits in several modes. Compile that exact
# source (pinned copy) against the four pinned libspeex builds and observe the
# test's own overwritten-byte check and ASan at the OOB sink. This is a
# regression test, not a network consumer, command or r5. Unpinned; not part
# of run-all.sh or the W245 witness check set.
set -u
cd "$(dirname "$0")/.."

SRC=pinned/debian-bits-boundary-1.2.1-4.c

clang -O0 -g -fno-omit-frame-pointer -fsanitize=address \
    -I src-vuln/include -I src-vuln "$SRC" \
    src-vuln/libspeex/.libs/libspeex.a -lm \
    -o evidence/debian-bound-asan-vuln 2>evidence/compile-debian-asan-vuln.log || exit 2
clang -O0 -g -fno-omit-frame-pointer -fsanitize=address \
    -I src-fixed/include -I src-fixed "$SRC" \
    src-fixed/libspeex/.libs/libspeex.a -lm \
    -o evidence/debian-bound-asan-fixed 2>evidence/compile-debian-asan-fixed.log || exit 2
gcc -O0 -g -I src-plain-vuln/include -I src-plain-vuln "$SRC" \
    src-plain-vuln/libspeex/.libs/libspeex.a -lm \
    -o evidence/debian-bound-plain-vuln 2>evidence/compile-debian-plain-vuln.log || exit 2
gcc -O0 -g -I src-plain-fixed/include -I src-plain-fixed "$SRC" \
    src-plain-fixed/libspeex/.libs/libspeex.a -lm \
    -o evidence/debian-bound-plain-fixed 2>evidence/compile-debian-plain-fixed.log || exit 2

# Each run is appended under a labeled header so the raw mode outputs and the
# return codes stay together in one evidence file per build.
asan_vuln=evidence/debian-boundary-asan-vuln.out
asan_fixed=evidence/debian-boundary-asan-fixed.out
plain_vuln=evidence/debian-boundary-plain-vuln.out
plain_fixed=evidence/debian-boundary-plain-fixed.out
: >"$asan_vuln"
: >"$asan_fixed"
: >"$plain_vuln"
: >"$plain_fixed"

asan_run() {
    local out=$1 bin=$2 mode=$3 rc
    ASAN_OPTIONS=detect_leaks=0 "$bin" "$mode" exact >>"$out" 2>&1
    rc=$?
    printf '=== mode=%s exact rc=%s\n' "$mode" "$rc" >>"$out"
}

plain_run() {
    local out=$1 bin=$2 mode=$3 rc
    "$bin" "$mode" >>"$out" 2>&1
    rc=$?
    printf '=== mode=%s rc=%s\n' "$mode" "$rc" >>"$out"
}

for mode in partial consumed full one; do
    asan_run "$asan_vuln" ./evidence/debian-bound-asan-vuln "$mode"
    asan_run "$asan_fixed" ./evidence/debian-bound-asan-fixed "$mode"
done
for mode in partial owned fits; do
    plain_run "$plain_vuln" ./evidence/debian-bound-plain-vuln "$mode"
    plain_run "$plain_fixed" ./evidence/debian-bound-plain-fixed "$mode"
done

fail=0
check() {
    if grep -q -- "$2" "$1"; then
        echo "PASS $3"
    else
        echo "FAIL $3"
        fail=$((fail+1))
    fi
}
check_no() {
    if grep -q -- "$2" "$1"; then
        echo "FAIL $3"
        fail=$((fail+1))
    else
        echo "PASS $3"
    fi
}
check "$asan_vuln" 'heap-buffer-overflow' 'ASan vulnerable partial heap overflow'
check "$asan_vuln" 'WRITE of size 1' 'ASan vulnerable WRITE of size 1'
check "$asan_vuln" 'bits.c:184' 'ASan vulnerable sink verbatim bits.c:184'
check "$asan_vuln" 'mode=consumed exact rc=1' 'ASan vulnerable consumed rc!=0'
check "$asan_vuln" 'mode=full exact rc=1' 'ASan vulnerable full rc!=0'
check "$asan_vuln" 'mode=one exact rc=1' 'ASan vulnerable one rc!=0'
check "$asan_fixed" 'mode=partial exact rc=0' 'ASan fixed partial rc=0'
check "$asan_fixed" 'after=120 capacity=16 overwritten=0' 'ASan fixed partial clean'
check_no "$asan_fixed" 'AddressSanitizer' 'ASan fixed: no report in any mode'
check "$asan_fixed" 'case=consumed before=128 consumed=4 after=88 capacity=16 overwritten=0' 'ASan fixed consumed no overflow'
check "$asan_fixed" 'case=full before=128 consumed=0 after=120 capacity=16 overwritten=0' 'ASan fixed full no overflow'
check "$asan_fixed" 'case=one before=8 consumed=0 after=0 capacity=1 overwritten=0' 'ASan fixed one no overflow'
check "$plain_vuln" 'overwritten=8' 'Debian test own check sees vulnerable overwrite'
check "$plain_vuln" 'mode=partial rc=1' 'Debian test vulnerable partial rc=1'
check "$plain_fixed" 'overwritten=0' 'Debian test fixed partial intact'
check "$plain_fixed" 'mode=partial rc=0' 'Debian test fixed partial rc=0'
check "$plain_vuln" 'mode=owned rc=0' 'vulnerable owner-buffer control rc=0'
check "$plain_fixed" 'mode=owned rc=0' 'fixed owner-buffer control rc=0'
check "$plain_vuln" 'mode=fits rc=0' 'vulnerable in-bounds control rc=0'
check "$plain_fixed" 'mode=fits rc=0' 'fixed in-bounds control rc=0'
echo "TOTAL fail=$fail"
exit "$fail"
