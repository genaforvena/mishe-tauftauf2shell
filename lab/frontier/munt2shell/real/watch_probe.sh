#!/bin/sh
# W179 replay: watch forged tail bytes after the real oversized memcpy.
# Prerequisite: real/build_and_run.sh produced build/vuln-2_8_3-plain/libmt32emu.a.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
g++ -std=c++11 -g -O1 \
	-I build/vuln-2_8_3-plain/include -I build/vuln-2_8_3-plain/include/mt32emu \
	driver.cpp build/vuln-2_8_3-plain/libmt32emu.a \
	-o build/driver-vuln-2_8_3-realalloc-plain
for p in watch_probe watch_probe_multi; do
	gdb -q -batch -x "$p.gdb" ./build/driver-vuln-2_8_3-realalloc-plain \
		>"evidence/${p}.out" 2>&1
	printf '=== %s ===\n' "$p"
	cat "evidence/${p}.out"
done
