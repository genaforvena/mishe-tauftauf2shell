#!/bin/sh
# W187: rebuild and run the fresh/preconditioned parser cases on both pinned
# libraries. No parser source byte is changed.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
mkdir -p evidence
: > evidence/precondition-results.txt

for variant in vuln-2_8_3 fixed-1749f7f; do
	for san in plain asan; do
		if [ "$san" = asan ]; then
			SAN_FLAGS="-fsanitize=address -fno-omit-frame-pointer"
		else
			SAN_FLAGS=""
		fi
		g++ -std=c++11 -g -O1 $SAN_FLAGS \
			-I "build/${variant}-${san}/include" -I "build/${variant}-${san}/include/mt32emu" \
			precondition_driver.cpp "build/${variant}-${san}/libmt32emu.a" -o "precondition-${variant}-${san}"
		for mode in fresh precondition; do
			tag="precondition-${variant}-${san}-${mode}"
			set +e
			ASAN_OPTIONS=detect_leaks=0 "./precondition-${variant}-${san}" "$mode" > "evidence/${tag}.out" 2>&1
			rc=$?
			set -e
			printf '%s rc=%d\n' "$tag" "$rc" | tee -a evidence/precondition-results.txt
			sed 's/^/  /' "evidence/${tag}.out" | tee -a evidence/precondition-results.txt
		done
	done
done
