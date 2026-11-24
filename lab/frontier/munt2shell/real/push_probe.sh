#!/bin/sh
# W184: replay the in-library pushSysex consumer probe. Two lab variants of
# the verbatim pinned trees are built as static libs with munt's own
# MT32EMU_WITH_TESTING accessor hooks enabled, so the upstream FakeROMs
# facility can OPEN a real Synth. No ROM is fetched, no host is contacted.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
mkdir -p evidence
: > evidence/push-results.txt

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
		push_driver.cpp "src/${variant}/mt32emu/src/test/FakeROMs.cpp" \
		"$bdir/libmt32emu.a" -Wl,--wrap=malloc -o "push-${variant}"
	for mode in shaped unshaped none safe fixed; do
		case "$variant:$mode" in
			fixed-1749f7f:shaped|fixed-1749f7f:unshaped|fixed-1749f7f:none|vuln-2_8_3:fixed) continue ;;
		esac
		tag="push-${variant}-${mode}"
		set +e
		"./push-${variant}" "$mode" > "evidence/${tag}.out" 2>&1
		rc=$?
		set -e
		printf '%s rc=%d\n' "$tag" "$rc" | tee -a evidence/push-results.txt
		sed 's/^/  /' "evidence/${tag}.out" | tee -a evidence/push-results.txt
	done
done

# Causal control against a stdio-consumed header: unbuffer stdout.
tag=push-vuln-2_8_3-shaped-nobuf
set +e
stdbuf -o0 ./push-vuln-2_8_3 shaped > "evidence/${tag}.out" 2>&1
rc=$?
set -e
printf '%s rc=%d\n' "$tag" "$rc" | tee -a evidence/push-results.txt
sed 's/^/  /' "evidence/${tag}.out" | tee -a evidence/push-results.txt
