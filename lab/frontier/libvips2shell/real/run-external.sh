#!/usr/bin/env bash
# Reproduce the W9 external-buffer negative-write controls inside the lab.
# Requires the pinned plain vulnerable/fixed builds (cfg-*-plain.log).
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
	$INC -o external-plain external.c -L"$VULN_LIB" -lvips $LIB || exit 1
gcc $CFLAGS -I"$ROOT/build-fixed-plain" -I"$ROOT/build-fixed-plain/libvips/include" \
	-I"$ROOT/src/libvips-fixed/libvips/include" $INC -o external-fixed external.c \
	-L"$FIXED_LIB" -lvips $LIB || exit 1

run() {
	local lib=$1 bin=$2 out=$3
	LD_LIBRARY_PATH="$lib" timeout 90 "./$bin" >"$out" 2>&1
	local rc=$?
	printf 'RUN_RC=%d\n' "$rc" >>"$out"
}

run "$VULN_LIB" external-plain external-vuln.out
run "$FIXED_LIB" external-fixed external-fixed.out

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

# Vulnerable: application-supplied buffer, chosen bytes in a mapped neighbour.
check external-vuln.out 'RESERVE base='
check external-vuln.out 'image=8589920000 line=4294960000'
check external-vuln.out 'pre=11'
check external-vuln.out 'IMAGE_OK sizeof_line=4294960000 sizeof_image=8589920000'
check external-vuln.out 'PAINT_PREPARE=0 bpl=-7296'
check external-vuln.out 'PAINT_DONE'
check external-vuln.out 'VICTIM_POST off=58272 byte0=5a byte1=5a before=11 after_end=5a'
check external-vuln.out 'RUN_RC=0'

# Fixed tree rejects the same geometry before the negative write.
check external-fixed.out 'dimension overflow'
absent external-fixed.out 'VICTIM_POST'
check external-fixed.out 'RESERVE base='
check external-fixed.out 'RUN_RC=0'

echo "RESULT fail=$fail"
exit "$fail"
