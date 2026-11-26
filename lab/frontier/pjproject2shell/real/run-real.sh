#!/usr/bin/env bash
# One-command real pjmedia AVI frame-pull replay: vulnerable vs fixed vs safe.
# Both pinned trees and their release-style (NDEBUG) ASan builds are local,
# gitignored bulk under src/full/ and build-vuln/ build-fixed/.
set -u
cd "$(dirname "$0")/.."

T=x86_64-pc-linux-gnu
VULN=src/full/pjproject-c1ea7648fb53f945493972a23133b9e0d3e4a1fe
FIXED=src/full/pjproject-7ecc6584969a923c4190b6912afbf5952b5a4b9f

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
    name=$1; avi=$2; mode=$3; log=$4
    mkdir -p "real/out-$name"
    ASAN_OPTIONS=detect_leaks=0:symbolize=1 \
        "./real/driver-$name" "real/$avi" "$mode" > "real/out-$name/$log" 2>&1
    rc=$?
    echo "RUN $name $avi $mode rc=$rc log=real/out-$name/$log"
    grep -E -m1 'ERROR: AddressSanitizer|WRITE of size|PULL_DONE|Assertion' \
        "real/out-$name/$log" || true
    grep -E -m1 'NEIGHBOR_AFTER|FORMAT ' "real/out-$name/$log" || true
}

python3 real/make_avi.py real/attack64.avi 64
python3 real/make_avi.py real/attack512.avi 512
python3 real/make_avi.py real/safe48.avi 48

compile vuln "$VULN"
run vuln attack64.avi exact vuln-attack64-exact.log
run vuln attack512.avi exact vuln-attack512-exact.log
run vuln attack64.avi neighbor vuln-attack64-neighbor.log
run vuln safe48.avi exact vuln-safe48-exact.log

compile fixed "$FIXED"
run fixed attack64.avi exact fixed-attack64-exact.log
run fixed safe48.avi exact fixed-safe48-exact.log

echo "== hashes =="
sha256sum real/attack64.avi real/attack512.avi real/safe48.avi
grep -n 'file_read3(fport->fd, frame->buf, ch.len' "$VULN/pjmedia/src/pjmedia/avi_player.c" "$FIXED/pjmedia/src/pjmedia/avi_player.c" || true
