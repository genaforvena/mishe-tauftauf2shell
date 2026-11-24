#!/bin/sh
# W183: replay the in-library consumer probe against the pinned plain static
# libs from build_and_run.sh. All inputs/outputs stay under real/.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
mkdir -p evidence
: > evidence/live-results.txt

for variant in vuln-2_8_3 fixed-1749f7f; do
	g++ -std=c++11 -g -O1 \
		-I "build/${variant}-plain/include" -I "build/${variant}-plain/include/mt32emu" \
		live_driver.cpp "build/${variant}-plain/libmt32emu.a" -Wl,--wrap=malloc -o "live-${variant}"
	for mode in shaped unshaped none safe fixed; do
		# Avoid meaningless cross-product runs: 'fixed' only on fixed lib,
		# attack modes only on vuln lib, 'safe' on both.
		case "$variant:$mode" in
			vuln-2_8_3:fixed|fixed-1749f7f:shaped|fixed-1749f7f:unshaped|fixed-1749f7f:none) continue ;;
		esac
		tag="live-${variant}-${mode}"
		set +e
		"./live-${variant}" "$mode" > "evidence/${tag}.out" 2>&1
		rc=$?
		set -e
		printf '%s rc=%d\n' "$tag" "$rc" | tee -a evidence/live-results.txt
		sed 's/^/  /' "evidence/${tag}.out" | tee -a evidence/live-results.txt
	done
done

# Causal control: unbuffered stdout removes the libc stdio allocation that
# consumes the forged top chunk. If the header change is caused by printDebug
# -> vprintf -> stdio buffer, this case must keep the forged bytes intact.
tag=live-vuln-2_8_3-shaped-nobuf
set +e
stdbuf -o0 ./live-vuln-2_8_3 shaped > "evidence/${tag}.out" 2>&1
rc=$?
set -e
printf '%s rc=%d\n' "$tag" "$rc" | tee -a evidence/live-results.txt
sed 's/^/  /' "evidence/${tag}.out" | tee -a evidence/live-results.txt
