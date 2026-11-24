#!/bin/sh
# W178: replay the real-malloc-neighbour probe against the pinned plain
# libraries from build_and_run.sh. All inputs/outputs stay under real/.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
mkdir -p evidence
: > evidence/neighbor-results.txt

for variant in vuln-2_8_3 fixed-1749f7f; do
	g++ -std=c++11 -g -O1 \
		-I "build/${variant}-plain/include" -I "build/${variant}-plain/include/mt32emu" \
		neighbor_driver.cpp "build/${variant}-plain/libmt32emu.a" -o "neighbor-${variant}"
	for mode in attack exact safe malloc; do
		tag="neighbor-${variant}-${mode}"
		set +e
		"./neighbor-${variant}" "$mode" > "evidence/${tag}.out" 2>&1
		rc=$?
		set -e
		printf '%s rc=%d\n' "$tag" "$rc" | tee -a evidence/neighbor-results.txt
		sed 's/^/  /' "evidence/${tag}.out" | tee -a evidence/neighbor-results.txt
	done
done
