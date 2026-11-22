#!/bin/sh
# Reproduce h2o2shell rungs 2/3/4 against both pinned h2o builds.
# Each build is a real libh2o.a compiled from the pinned source tree.
set -u
cd "$(dirname "$0")/.." || exit 1

INC_COMMON="-I klib -I picohttpparser -I picotls/include -I quicly/include"
LIBS="-lpthread -ldl -lssl -lcrypto -lz -lbrotlidec -lbrotlienc -lzstd -lm -luv"
ASAN="-fsanitize=address -fno-omit-frame-pointer -g -O0"
PLAIN="-g -O0"

compile() {
    out=$1; pin=$2; bdir=$3; cflags=$4; defs=$5
    # shellcheck disable=SC2086
    gcc $cflags $defs -I "src/$pin/include" -I "src/$pin/$bdir/include" \
        -I "src/$pin/deps/klib" -I "src/$pin/deps/picohttpparser" \
        -I "src/$pin/deps/picotls/include" -I "src/$pin/deps/quicly/include" \
        harness/logconf_harness.c "src/$pin/$bdir/libh2o.a" \
        -o "$out" $LIBS || exit 1
}

compile harness/lc-vuln-asan    vuln  build-asan  "$ASAN" ""
compile harness/lc-fixed-asan   fixed build-asan  "$ASAN" ""
compile harness/lc-vuln-plain   vuln  build-plain "$PLAIN" "-DPLAIN_READBACK"
compile harness/lc-fixed-plain  fixed build-plain "$PLAIN" "-DPLAIN_READBACK"
compile harness/lc-vuln-safe    vuln  build-plain "$PLAIN" "-DPLAIN_READBACK -DCHOICE_LEN=8"
compile harness/lc-fixed-safe   fixed build-plain "$PLAIN" "-DPLAIN_READBACK -DCHOICE_LEN=8"

run() {
    name=$1; bin=$2
    ASAN_OPTIONS=detect_leaks=0 "$bin" > "harness/out-$name.txt" 2>&1
    rc=$?
    printf '%s rc=%s\n' "$name" "$rc"
    printf '%s\n' "$rc" > "harness/out-$name.rc"
}

run vuln-asan    ./harness/lc-vuln-asan
run fixed-asan   ./harness/lc-fixed-asan
run vuln-plain   ./harness/lc-vuln-plain
run fixed-plain  ./harness/lc-fixed-plain
run vuln-safe    ./harness/lc-vuln-safe
run fixed-safe   ./harness/lc-fixed-safe
