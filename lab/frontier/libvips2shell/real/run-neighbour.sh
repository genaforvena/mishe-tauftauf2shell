#!/usr/bin/env bash
# Reproduce the W6 allocator-neighbour controls for CVE-2026-69242 inside the
# lab. Requires the pinned plain vulnerable/fixed builds prepared by
# ../build.sh-style meson/ninja runs (cfg-vuln-plain.log, cfg-fixed-plain.log).
set -u
cd "$(dirname "$0")" || exit 1

ROOT=$(cd .. && pwd)
VULN_LIB="$ROOT/build-vuln-plain/libvips"
FIXED_LIB="$ROOT/build-fixed-plain/libvips"
for d in "$VULN_LIB" "$FIXED_LIB"; do
	if [ ! -f "$d/libvips.so.42" ]; then
		echo "MISSING BUILD: $d" >&2
		exit 2
	fi
done

INC="$(pkg-config --cflags glib-2.0 gobject-2.0) -I$ROOT/src/libvips-8.18.2/libvips/include"
LIB=$(pkg-config --libs glib-2.0 gobject-2.0)
CFLAGS="-g -O0 -DHAVE_CONFIG_H"

gcc $CFLAGS -I"$ROOT/build-vuln-plain" -I"$ROOT/build-vuln-plain/libvips/include" \
	$INC -o neighbour-plain neighbour.c -L"$VULN_LIB" -lvips $LIB || exit 1
gcc $CFLAGS -I"$ROOT/build-fixed-plain" -I"$ROOT/build-fixed-plain/libvips/include" \
	-I"$ROOT/src/libvips-fixed/libvips/include" $INC -o neighbour-fixed neighbour.c \
	-L"$FIXED_LIB" -lvips $LIB || exit 1

run() {
	local lib=$1 bin=$2 out=$3 mode=$4
	LD_LIBRARY_PATH="$lib" timeout 90 "./$bin" "$mode" >"$out" 2>&1
	local rc=$?
	printf 'RUN_RC=%d\n' "$rc" >>"$out"
}

run "$VULN_LIB" neighbour-plain neighbour-layout.out layout
run "$VULN_LIB" neighbour-plain neighbour-victim.out victim
run "$FIXED_LIB" neighbour-fixed neighbour-fixed-layout.out layout
run "$FIXED_LIB" neighbour-fixed neighbour-fixed-victim.out victim

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

# Default layout: the negative-offset target is an unmapped glibc mmap gap.
check neighbour-layout.out 'sizeof_line=4294960000 sizeof_image=8589920000'
check neighbour-layout.out 'DELTA=-7264'
check neighbour-layout.out 'MINCORE_TARGET=0 errno=12'
check neighbour-layout.out 'bpl=-7296 lskip=18446744073709544320'
absent neighbour-layout.out 'PAINT_DONE'
check neighbour-layout.out 'RUN_RC=139'

# Explicit neighbour: chosen bytes reach a different live mapping.
check neighbour-victim.out 'pre=11'
check neighbour-victim.out 'PAINT_DONE'
check neighbour-victim.out 'VICTIM_POST off=58272 byte0=5a byte1=5a before=11 after_end=5a'
check neighbour-victim.out 'RUN_RC=0'

# Fixed tree rejects the geometry before any paint runs.
check neighbour-fixed-layout.out 'PREPARE=ERR msg=image: dimension overflow'
absent neighbour-fixed-layout.out 'PAINT_DONE'
check neighbour-fixed-victim.out 'PREPARE=ERR msg=image: dimension overflow'
absent neighbour-fixed-victim.out 'VICTIM_POST'

echo "RESULT fail=$fail"
exit "$fail"
