#!/bin/sh
# Independent-compiler confirmation on the real pinned library: clang++ ASan
# for the public C API attack path (vuln 2.8.3 vs pinned fix 1749f7f).
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"

for variant in vuln-2_8_3 fixed-1749f7f; do
	bdir="build/${variant}-clang-asan"
	cmake -S "src/${variant}/mt32emu" -B "$bdir" \
		-DBUILD_TESTING=FALSE -DBUILD_SHARED_LIBS=FALSE \
		-DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug \
		-DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" >/dev/null
	cmake --build "$bdir" --target mt32emu -j 4 >/dev/null
	clang++ -std=c++11 -g -O1 -fsanitize=address -fno-omit-frame-pointer \
		-I "$bdir/include" -I "$bdir/include/mt32emu" \
		driver.cpp "$bdir/libmt32emu.a" -o "driver-${variant}-clang-asan"
	set +e
	"./driver-${variant}-clang-asan" capi-attack >"evidence/${variant}-clang-asan-capi-attack.out" 2>&1
	rc=$?
	set -e
	printf '%s clang-asan capi-attack rc=%d\n' "$variant" "$rc" | tee -a evidence/results.txt
done
