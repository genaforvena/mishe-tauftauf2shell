#!/bin/sh
# W182 replay: post-overflow second-call state reuse through the public API.
# Prerequisite: real/build_and_run.sh has produced build/*-plain/libmt32emu.a.
# Outputs stay under real/evidence/; no network, no external target.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
for v in vuln-2_8_3 fixed-1749f7f; do
	g++ -std=c++11 -g -O1 -Wno-stringop-overflow \
		-I "build/${v}-plain/include" -I "build/${v}-plain/include/mt32emu" \
		reuse_driver.cpp "build/${v}-plain/libmt32emu.a" -o "build/reuse-${v}"
	for m in repeat safe baseline; do
		mode="${v%%-*}-${m}"
		set +e
		"./build/reuse-${v}" "$mode" >"evidence/reuse-${mode}.out" 2>&1
		rc=$?
		set -e
		printf 'reuse-%s rc=%d\n' "$mode" "$rc"
		cat "evidence/reuse-${mode}.out"
	done
done
