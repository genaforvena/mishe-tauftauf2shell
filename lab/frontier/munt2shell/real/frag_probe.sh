#!/bin/sh
# Replay the isolated fragment-boundary probe against the pinned real library.
# Requires the static libraries built by build_and_run.sh (or
# build_clang_asan.sh) under real/build/. No network access, no source rebuild.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"

mkdir -p evidence

build_and_run() {
	label=$1      # e.g. gcc-vuln-asan
	bdir=$2       # e.g. build/vuln-2_8_3-asan
	compiler=$3   # g++ or clang++
	san=$4        # asan or plain
	extra=""
	driverflag=""
	if [ "$san" = asan ]; then
		extra="-fsanitize=address -fno-omit-frame-pointer -g -O1"
	else
		extra="-g -O1"
		driverflag="-DREAL_TAIL_PROBE"
	fi
	bin="frag-${label}"
	$compiler -std=c++11 -g -O1 $driverflag $extra \
		-I "$bdir/include" -I "$bdir/include/mt32emu" \
		frag_driver.cpp "$bdir/libmt32emu.a" -o "$bin"
	for mode in frag-many single-32768 single-32769 single-40001; do
		tag="frag-${label}-${mode}"
		set +e
		ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 \
			"./$bin" "$mode" >"evidence/${tag}.out" 2>&1
		rc=$?
		set -e
		printf '%s rc=%d\n' "$tag" "$rc" | tee -a evidence/frag-results.txt
	done
}

: > evidence/frag-results.txt
build_and_run gcc-vuln-asan   build/vuln-2_8_3-asan         g++      asan
build_and_run gcc-fixed-asan  build/fixed-1749f7f-asan      g++      asan
build_and_run clang-vuln-asan build/vuln-2_8_3-clang-asan   clang++  asan
build_and_run gcc-vuln-plain  build/vuln-2_8_3-plain        g++      plain
