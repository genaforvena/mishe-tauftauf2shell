#!/bin/sh
# W186: one bounded short-overflow partial-pointer experiment against the
# pinned plain libraries built by build_and_run.sh. No library source changes.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
mkdir -p evidence
: > evidence/partial-results.txt

for variant in vuln-2_8_3 fixed-1749f7f; do
	g++ -std=c++11 -g -O1 \
		-I "build/${variant}-plain/include" -I "build/${variant}-plain/include/mt32emu" \
		partial_driver.cpp "build/${variant}-plain/libmt32emu.a" -o "partial-${variant}"
	for mode in attack safe; do
		tag="partial-${variant}-${mode}"
		set +e
		"./partial-${variant}" "$mode" > "evidence/${tag}.out" 2>&1
		rc=$?
		set -e
		printf '%s rc=%d\n' "$tag" "$rc" | tee -a evidence/partial-results.txt
		sed 's/^/  /' "evidence/${tag}.out" | tee -a evidence/partial-results.txt
	done
done
# Independent allocator check: ASan must flag the 17-byte overflow on the
# vulnerable library and stay clean on the fixed one. ASan's redzones change
# the neighbour layout, so no marker claim comes from this control.
for variant in vuln-2_8_3 fixed-1749f7f; do
	g++ -std=c++11 -g -O1 -fsanitize=address -fno-omit-frame-pointer \
		-I "build/${variant}-asan/include" -I "build/${variant}-asan/include/mt32emu" \
		partial_driver.cpp "build/${variant}-asan/libmt32emu.a" -o "partial-${variant}-asan"
	tag="partial-${variant}-asan-attack"
	set +e
	ASAN_OPTIONS=detect_leaks=0 "./partial-${variant}-asan" attack > "evidence/${tag}.out" 2>&1
	rc=$?
	set -e
	printf '%s rc=%d\n' "$tag" "$rc" | tee -a evidence/partial-results.txt
	sed 's/^/  /' "evidence/${tag}.out" | tee -a evidence/partial-results.txt
done
