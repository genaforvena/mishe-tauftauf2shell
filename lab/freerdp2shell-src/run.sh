#!/bin/sh
# Real-library replay for FreeRDP rdpsnd select_format() wraparound
# (GHSA-3m9q-g533-rqjq / CVE-2026-114045).
#
# Provisions FreeRDP 3.32.0 under $WORK (default /tmp/fr-wake2), builds the
# three libraries needed by the advisory PoC with gcc ASan/UBSan, compiles
# the PoC and the benign PCM control, and checks the observed output.
#
# This is IN-PROCESS: formats are injected into ctx->client_formats directly.
# It does NOT exercise the SNDC_FORMATS wire parse, RDP auth, or a live server.
# Only loopback-local, source-built code is used; no external probes.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORK=${FREERDP_WORK:-/tmp/fr-wake2}
SRC=$WORK/src3320
BUILD=$WORK/build3320
TAG=3.32.0
CLONE_URL=${FREERDP_CLONE_URL:-https://github.com/FreeRDP/FreeRDP.git}
ASAN='detect_leaks=0:allocator_may_return_null=1:abort_on_error=0'

fail() { echo "FAIL: $*" >&2; exit 1; }

if [ ! -d "$SRC/.git" ]; then
    mkdir -p "$WORK"
    git clone --depth 1 --branch "$TAG" "$CLONE_URL" "$SRC"
fi

if [ ! -f "$BUILD/server/common/libfreerdp-server3.so" ]; then
    # KRB5/PKCS11 off and CLIENT off keep the build inside this lane; the
    # X11 shadow subsystem is not built (missing XShmSegmentInfo on this host).
    cmake -S "$SRC" -B "$BUILD" -GNinja \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1' \
        -DWITH_SERVER=ON -DWITH_CLIENT=OFF -DWITH_SERVER_CHANNELS=ON \
        -DWITH_KRB5=OFF -DWITH_PKCS11=OFF -DWITH_SMARTCARD_EMULATE=OFF
    # If ninja loops on "Re-running CMake..." for minutes, the generated
    # CMakeFiles/rules.ninja VERIFY_GLOBS rule needs `restat = 1` added after
    # its `generator = 1` line. This is a scratch generated file, not repo code.
    ninja -C "$BUILD" -j16 libwinpr3.so libfreerdp3.so libfreerdp-server3.so
fi

compile() { # src out
    gcc -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -std=gnu11 \
        -Wno-deprecated-declarations \
        -I"$SRC/winpr/include" -I"$BUILD/winpr/include" -I"$BUILD" \
        -I"$BUILD/include" -I"$SRC/include" -I"$SRC/channels/rdpsnd/server" \
        "$1" -o "$2" \
        -L"$BUILD/libfreerdp" -L"$BUILD/winpr/libwinpr" -L"$BUILD/server/common" \
        -Wl,-rpath,"$BUILD/libfreerdp:$BUILD/winpr/libwinpr:$BUILD/server/common" \
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

echo 'ALL REAL-LIBRARY CHECKS PASS'
echo "vulnerable: $WORK/poc.out"
echo "control:    $WORK/pcm.out"
