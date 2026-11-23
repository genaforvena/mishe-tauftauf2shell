#!/usr/bin/env bash
# Reproduce the W3 real-consumer controls for CVE-2026-69242 inside the lab.
# Requires the pinned vulnerable and fixed ASan builds prepared by
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

INC="$(pkg-config --cflags glib-2.0 gobject-2.0) -I$ROOT/src/libvips-8.18.2/libvips/include"
LIB=$(pkg-config --libs glib-2.0 gobject-2.0)
CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O0 -DHAVE_CONFIG_H"

gcc $CFLAGS -I"$ROOT/build-vuln-asan" -I"$ROOT/build-vuln-asan/libvips/include" \
	$INC -o consumer-vuln consumer.c -L"$VULN_LIB" -lvips $LIB || exit 1
gcc $CFLAGS -I"$ROOT/build-fixed-asan" -I"$ROOT/build-fixed-asan/libvips/include" \
	-I"$ROOT/src/libvips-fixed/libvips/include" $INC -o consumer-fixed consumer.c \
	-L"$FIXED_LIB" -lvips $LIB || exit 1

run() {
	local lib=$1 bin=$2 out=$3 mode=$4
	LD_LIBRARY_PATH="$lib" ASAN_OPTIONS=detect_leaks=0 \
		timeout 150 "./$bin" "$mode" >"$out" 2>&1
}

run "$VULN_LIB" consumer-vuln consumer-region.out region || true
run "$VULN_LIB" consumer-vuln consumer-extract.out extract || true
run "$FIXED_LIB" consumer-fixed consumer-fixed-extract.out extract || true

fail=0
check() {
	if grep -qF "$2" "$1"; then
		echo "PASS $1 :: $2"
	else
		echo "FAIL $1 :: $2"
		fail=1
	fi
}
absent() {
	if grep -qF "$2" "$1"; then
		echo "FAIL $1 :: must not contain $2"
		fail=1
	else
		echo "PASS $1 :: absent $2"
	fi
}

# Real libvips memory image with the geometry the real TIFF loader accepts.
check consumer-region.out 'sizeof_line=4294960000 sizeof_image=8589920000'
check consumer-region.out 'REGION_PREPARE=0'
check consumer-region.out 'bpl=-7296 lskip=18446744073709544320'
check consumer-region.out 'The signal is caused by a READ memory access.'
check consumer-region.out 'consumer.c:82'

# Real downstream operation: vips_extract_area + vips_image_write_to_memory.
check consumer-extract.out 'EXTRACT=OK Xsize=4 Ysize=2 Bands=10000 sizeof_line=160000'
check consumer-extract.out 'heap-buffer-overflow'
check consumer-extract.out 'READ of size 160000'
check consumer-extract.out 'vips_region_copy ../src/libvips-8.18.2/libvips/iofuncs/region.c:1090'
check consumer-extract.out '6144 bytes before 8589920016-byte region'

# Fixed tree: same geometry rejected before any consumer runs.
check consumer-fixed-extract.out 'PREPARE=ERR msg=image: dimension overflow'
absent consumer-fixed-extract.out 'heap-buffer-overflow'

echo "RESULT fail=$fail"
exit "$fail"
