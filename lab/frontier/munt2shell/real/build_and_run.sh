#!/bin/sh
# Build pinned libmt32emu 2.8.3 (vuln) and the same tree with pinned fix
# 1749f7f (fixed) as static libraries under gcc, then drive the real
# DefaultMidiStreamParser / MidiStreamParser with a single oversized SysEx.
# All inputs and outputs stay under lab/frontier/munt2shell/real/.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"

mkdir -p build evidence

configure_and_build() {
	variant=$1
	mode=$2
	srcdir="src/${variant}"
	bdir="build/${variant}-${mode}"
	if [ "$mode" = asan ]; then
		extra="-fsanitize=address -fno-omit-frame-pointer -g -O1"
	else
		extra="-g -O1"
	fi
	cmake -S "$srcdir/mt32emu" -B "$bdir" \
		-DBUILD_TESTING=FALSE -DBUILD_SHARED_LIBS=FALSE \
		-DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="$extra" >/dev/null
	cmake --build "$bdir" --target mt32emu -j 4 >/dev/null
	driverflag=""
	if [ "$mode" = plain ]; then driverflag="-DREAL_TAIL_PROBE"; fi
	g++ -std=c++11 -g -O1 $driverflag $extra \
		-I "$bdir/include" -I "$bdir/include/mt32emu" \
		driver.cpp "$bdir/libmt32emu.a" -o "driver-${variant}-${mode}"
}

for variant in vuln-2_8_3 fixed-1749f7f; do
	for mode in asan plain; do
		configure_and_build "$variant" "$mode"
	done
done

for variant in vuln-2_8_3 fixed-1749f7f; do
	for mode in asan plain; do
		bin="./driver-${variant}-${mode}"
		for scenario in default-attack default-baseline count-attack count-baseline count-fragment count-attack-complete capi-attack capi-baseline; do
			tag="${variant}-${mode}-${scenario}"
			set +e
			"$bin" "$scenario" >"evidence/${tag}.out" 2>&1
			rc=$?
			set -e
			printf '%s rc=%d\n' "$tag" "$rc" | tee -a evidence/results.txt
		done
	done
done
