#!/bin/sh
# W179 replay: forge the top-chunk size with attack bytes, then allocate.
# Prerequisite: real/build_and_run.sh has produced build/*-plain/libmt32emu.a.
# Outputs stay under real/evidence/; no network, no external target.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
for v in vuln-2_8_3 fixed-1749f7f; do
	g++ -std=c++11 -g -O1 -Wno-stringop-overflow \
		-I "build/${v}-plain/include" -I "build/${v}-plain/include/mt32emu" \
		shape_driver.cpp "build/${v}-plain/libmt32emu.a" -o "build/shape-${v}"
	for m in shape attack safe; do
		set +e
		"./build/shape-${v}" "$m" >"evidence/shape-${v}-${m}.out" 2>&1
		rc=$?
		set -e
		printf 'shape-%s-%s rc=%d\n' "$v" "$m" "$rc"
		cat "evidence/shape-${v}-${m}.out"
	done
done
