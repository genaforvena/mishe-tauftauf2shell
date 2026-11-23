#!/bin/sh
# Bounded replay of the write-alphabet experiment (W170). Reuses the existing
# CMake-built static libraries under build/; never rebuilds or modifies them.
# Evidence lands in evidence/alphabet-* only.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
mkdir -p evidence

COMMON="-std=c++11 -g -O1"
g++ $COMMON -DREAL_TAIL_PROBE \
	-I build/vuln-2_8_3-plain/include -I build/vuln-2_8_3-plain/include/mt32emu \
	alphabet_driver.cpp build/vuln-2_8_3-plain/libmt32emu.a -o alphabet-vuln-plain

g++ $COMMON -fsanitize=address -fno-omit-frame-pointer -g -O1 \
	-I build/vuln-2_8_3-asan/include -I build/vuln-2_8_3-asan/include/mt32emu \
	alphabet_driver.cpp build/vuln-2_8_3-asan/libmt32emu.a -o alphabet-vuln-asan

g++ $COMMON -fsanitize=address -fno-omit-frame-pointer -g -O1 \
	-I build/fixed-1749f7f-asan/include -I build/fixed-1749f7f-asan/include/mt32emu \
	alphabet_driver.cpp build/fixed-1749f7f-asan/libmt32emu.a -o alphabet-fixed-asan

: > evidence/alphabet-results.txt
run_case() {
	bin=$1
	tag=$2
	mode=$3
	length=$4
	offset=$5
	byte=$6
	set +e
	"$bin" "$mode" "$length" "$offset" "$byte" >"evidence/alphabet-${tag}.out" 2>&1
	rc=$?
	set -e
	printf '%s rc=%d\n' "$tag" "$rc" | tee -a evidence/alphabet-results.txt
}

# Plain build: chosen-byte readback past the real 32768-byte allocation.
run_case ./alphabet-vuln-plain vuln-plain-all-7f all-7f 40001 -1 0
run_case ./alphabet-vuln-plain vuln-plain-status80-at-32768 status80-at-32768 40001 32768 80
run_case ./alphabet-vuln-plain vuln-plain-status85-at-32768 status85-at-32768 40001 32768 85
run_case ./alphabet-vuln-plain vuln-plain-f7-at-32768 f7-at-32768 40001 32768 f7
run_case ./alphabet-vuln-plain vuln-plain-f8-at-32768 f8-at-32768 40001 32768 f8
run_case ./alphabet-vuln-plain vuln-plain-status80-at-32769 status80-at-32769 40001 32769 80
run_case ./alphabet-vuln-plain vuln-plain-7f-at-32768 7f-at-32768 40001 32768 7f

# ASan with the real allocator: rc 1 only where a 7-bit-only copy overruns.
run_case ./alphabet-vuln-asan vuln-asan-all-7f all-7f 40001 -1 0
run_case ./alphabet-vuln-asan vuln-asan-status80-at-32768 status80-at-32768 40001 32768 80
run_case ./alphabet-vuln-asan vuln-asan-f7-at-32768 f7-at-32768 40001 32768 f7
run_case ./alphabet-vuln-asan vuln-asan-7f-at-32768 7f-at-32768 40001 32768 7f
run_case ./alphabet-fixed-asan fixed-asan-all-7f all-7f 40001 -1 0
