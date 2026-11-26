#!/bin/sh
# Reproduce the libmikmod DSM_Load track-count truncation on two pinned trees.
# Public tarballs are provisioning only; all execution is local, no sockets,
# no audio device (only drv_nos is registered), no external probes.
set -u
cd "$(dirname "$0")"

VULN=08d7d2106ce3d1d6ef1dddb060e04a10b7dc8ae2
FIXED=a125eabbd086f311496ae46d08aaebcad0a1c426
VULN_SHA=dbe73e92401f7e12d2153169b15da2f9981bc8323395d5dc2e35e08946f56f42
FIXED_SHA=a9d7cba3e1867fefbf385cb16da859d23e042fbe54a8ee370ced963d5e537f44

mkdir -p src build/vuln build/fixed evidence inputs
echo "== tarballs =="
sha256sum src/vuln.tar.gz src/fixed.tar.gz

for pair in "vuln:$VULN" "fixed:$FIXED"; do
	pin=${pair%%:*}
	sha=${pair#*:}
	tree="src/mikmod-$sha"
	if [ ! -f "$tree/libmikmod/loaders/load_dsm.c" ]; then
		tar xzf "src/$pin.tar.gz" -C src
	fi
	echo "== $pin pinned load_dsm.c =="
	sha256sum "$tree/libmikmod/loaders/load_dsm.c"
	cmake -S "$tree/libmikmod" -B "build/$pin/lib" \
		-DCMAKE_BUILD_TYPE=Debug \
		-DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O1' \
		-DCMAKE_SHARED_LINKER_FLAGS='-fsanitize=address' \
		> "build/$pin/cmake.log" 2>&1
	cmake --build "build/$pin/lib" --target mikmod-static -j4 \
		>> "build/$pin/cmake.log" 2>&1 || { tail -20 "build/$pin/cmake.log"; exit 1; }
	gcc -fsanitize=address -fno-omit-frame-pointer -g -O1 \
		-I "$tree/libmikmod/include" -I "build/$pin/lib" \
		harness/driver.c "build/$pin/lib/libmikmod.a" -o "build/$pin/driver" -lm
done

echo "== generated inputs =="
python3 harness/make_dsm.py inputs
sha256sum inputs/*.dsm

for pin in vuln fixed; do
	for case in attack attack16 safe; do
		ASAN_OPTIONS=detect_leaks=0 "./build/$pin/driver" "inputs/$case.dsm" \
			> "evidence/$pin-asan-$case.out" 2>&1
		printf '%s %s rc=%s\n' "$pin" "$case" "$?"
	done
done

echo "== evidence hashes =="
sha256sum evidence/*.out harness/driver.c harness/make_dsm.py run-all.sh verify.sh
