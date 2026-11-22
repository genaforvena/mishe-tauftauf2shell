#!/bin/sh
# Independent replay: rebuild both pins from git-archive HEAD (tracked bytes
# only), recompile the harness and compare normalized evidence hashes.
set -eu
cd "$(dirname "$0")/.." || exit 1
ROOT=$(pwd)
REPLAY="$ROOT/replay"
rm -rf "$REPLAY"
mkdir -p "$REPLAY/vuln" "$REPLAY/fixed"

for pin in vuln fixed; do
    git -C "src/$pin" archive HEAD | tar -x -C "$REPLAY/$pin"
done

LIBS="-lpthread -ldl -lssl -lcrypto -lz -lbrotlidec -lbrotlienc -lzstd -lm -luv"
build_lib() {
    pin=$1; bdir=$2; cflags=$3
    (cd "$REPLAY/$pin" && cmake -S . -B "$bdir" -DCMAKE_BUILD_TYPE=Debug \
        -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_FLAGS="$cflags" \
        -DCMAKE_EXE_LINKER_FLAGS="$cflags" >/dev/null && \
        cmake --build "$bdir" --target libh2o -j4 >/dev/null)
}

build_lib vuln  build-asan  '-fsanitize=address -fno-omit-frame-pointer -g -O0'
build_lib fixed build-asan  '-fsanitize=address -fno-omit-frame-pointer -g -O0'
build_lib vuln  build-plain '-g -O0'
build_lib fixed build-plain '-g -O0'
echo "libraries rebuilt from archives"

compile() {
    out=$1; pin=$2; bdir=$3; cflags=$4; defs=$5
    # shellcheck disable=SC2086
    gcc $cflags $defs -I "$REPLAY/$pin/include" -I "$REPLAY/$pin/$bdir/include" \
        -I "$REPLAY/$pin/deps/klib" -I "$REPLAY/$pin/deps/picohttpparser" \
        -I "$REPLAY/$pin/deps/picotls/include" -I "$REPLAY/$pin/deps/quicly/include" \
        "$ROOT/harness/logconf_harness.c" "$REPLAY/$pin/$bdir/libh2o.a" \
        -o "$out" $LIBS
}

A='-fsanitize=address -fno-omit-frame-pointer -g -O0'
P='-g -O0'
compile "$REPLAY/lc-vuln-asan"   vuln  build-asan  "$A" ''
compile "$REPLAY/lc-fixed-asan"  fixed build-asan  "$A" ''
compile "$REPLAY/lc-vuln-plain"  vuln  build-plain "$P" '-DPLAIN_READBACK'
compile "$REPLAY/lc-fixed-plain" fixed build-plain "$P" '-DPLAIN_READBACK'
compile "$REPLAY/lc-vuln-safe"   vuln  build-plain "$P" '-DPLAIN_READBACK -DCHOICE_LEN=8'
compile "$REPLAY/lc-fixed-safe"  fixed build-plain "$P" '-DPLAIN_READBACK -DCHOICE_LEN=8'

for v in vuln-asan fixed-asan vuln-plain fixed-plain vuln-safe fixed-safe; do
    set +e
    ASAN_OPTIONS=detect_leaks=0 "$REPLAY/lc-$v" > "$REPLAY/out-$v.txt" 2>&1
    printf '%s\n' "$?" > "$REPLAY/out-$v.rc"
    set -e
done

python3 "$ROOT/harness/normalize.py" "$REPLAY" > "$REPLAY/EVIDENCE_HASHES.txt"
echo "--- in-tree ---"
cat "$ROOT/harness/EVIDENCE_HASHES.txt"
echo "--- clean archive ---"
cat "$REPLAY/EVIDENCE_HASHES.txt"
if cmp -s "$ROOT/harness/EVIDENCE_HASHES.txt" "$REPLAY/EVIDENCE_HASHES.txt"; then
    echo "REPLAY_IDENTICAL=yes"
else
    echo "REPLAY_IDENTICAL=no"
fi
