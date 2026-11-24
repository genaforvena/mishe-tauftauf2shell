#!/bin/sh
# W185: real-library readback check. Build the verbatim pinned vulnerable and
# fixed trees as the same labelled MT32EMU_WITH_TESTING static-lib variant used
# in W184, drive a real Synth with FakeROMs, and watch a chosen overflow byte
# through the later dispatch and render. No ROM fetched, no host contacted.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
mkdir -p evidence
: > evidence/render-results.txt

for variant in vuln-2_8_3 fixed-1749f7f; do
	bdir="build/${variant}-testing"
	cmake -S "src/${variant}/mt32emu" -B "$bdir" \
		-DBUILD_TESTING=FALSE -DBUILD_SHARED_LIBS=FALSE \
		-DCMAKE_BUILD_TYPE=Debug \
		-DCMAKE_CXX_FLAGS="-g -O1 -DMT32EMU_WITH_TESTING" >/dev/null
	cmake --build "$bdir" --target mt32emu -j 4 >/dev/null
	g++ -std=c++11 -g -O1 \
		-I "$bdir/include" -I "$bdir/include/mt32emu" \
		-I "src/${variant}/mt32emu/src" \
		render_driver.cpp "src/${variant}/mt32emu/src/test/FakeROMs.cpp" \
		"$bdir/libmt32emu.a" -Wl,--wrap=malloc -o "render-${variant}"
	for mode in render-attack render-safe; do
		tag="render-${variant}-${mode}"
		set +e
		"./render-${variant}" "$mode" > "evidence/${tag}.out" 2>&1
		rc=$?
		set -e
		printf '%s rc=%d\n' "$tag" "$rc" | tee -a evidence/render-results.txt
		sed 's/^/  /' "evidence/${tag}.out" | tee -a evidence/render-results.txt
	done
done

# Hardware watchpoint in the vulnerable plain build, from just after the
# memcpy through the real later dispatch and four render calls.
gdb -q -batch -x render_watch.gdb --args ./render-vuln-2_8_3 render-attack \
	> evidence/render-watch.out 2>&1 || true
printf 'render-watch.out lines=%s\n' "$(wc -l < evidence/render-watch.out)" \
	| tee -a evidence/render-results.txt
