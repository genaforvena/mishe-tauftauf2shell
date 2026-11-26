#!/usr/bin/env bash
# sailtga2shell w1: verify which public SAIL memory entry points reach the
# tga.c:269 sink. Uses the builds produced by run-all.sh; adds no pinned file.
set -u
cd "$(dirname "$0")/.."
ROOT="$PWD"
mkdir -p evidence-w1

pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
need() { grep -q -- "$2" "$1" 2>/dev/null; }

compile_mem() {
    tag=$1; src=$2; cc=$3; mode=$4
    if [ "$mode" = asan ]; then
        cflags="-fsanitize=address -fno-omit-frame-pointer -g -O0"
        ldflags="-fsanitize=address"
    else
        cflags="-g -O0"; ldflags=""
    fi
    [ "$src" = sail-1.0.0 ] && cflags="$cflags -I$ROOT/stubs"
    $cc $cflags -I "$src/src" -I "build-$tag/include" harness/memory-driver.c \
        -Wl,--start-group build-$tag/src/sail/libsail.a \
        build-$tag/src/sail-codecs-archive/libsail-codecs.a \
        build-$tag/src/sail-common/libsail-common.a \
        build-$tag/src/sail-manip/libsail-manip.a -Wl,--end-group \
        -lm $ldflags -o "evidence-w1/mem-$tag" 2> "evidence-w1/compile-$tag.log"
}

for spec in 'vuln-gcc-asan sail-0.9.10 gcc asan' \
            'vuln-plain sail-0.9.10 gcc plain' \
            'fixed-plain sail-1.0.0 gcc plain'; do
    set -- $spec
    compile_mem "$1" "$2" "$3" "$4" && ok "compile memory driver $1" || bad "compile memory driver $1"
done

echo "== junior memory API cannot auto-detect TGA (negative result) =="
./evidence-w1/mem-vuln-plain evidence/attack.tga junior > evidence-w1/junior-plain-attack.out 2>&1
if need evidence-w1/junior-plain-attack.out 'rc=301' \
   && need evidence-w1/junior-plain-attack.out 'SAIL_ERROR_CODEC_NOT_FOUND'; then
    ok "sail_load_from_memory TGA auto-probe rejected (rc=301)"
else
    bad "sail_load_from_memory TGA auto-probe rejected (rc=301)"
fi

echo "== explicit-codec memory path: ASan corruption =="
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 ./evidence-w1/mem-vuln-gcc-asan \
    evidence/attack.tga explicit > evidence-w1/asan-mem-attack.out 2>&1
need evidence-w1/asan-mem-attack.out 'ERROR: AddressSanitizer: heap-buffer-overflow' \
    && ok "memory API ASan heap-buffer-overflow" || bad "memory API ASan heap-buffer-overflow"
need evidence-w1/asan-mem-attack.out 'WRITE of size 4' \
    && ok "memory API ASan WRITE of size 4" || bad "memory API ASan WRITE of size 4"
need evidence-w1/asan-mem-attack.out 'tga.c:269' \
    && ok "memory API ASan frame at verbatim tga.c:269" || bad "memory API ASan frame at verbatim tga.c:269"
need evidence-w1/asan-mem-attack.out '0 bytes after 256-byte region' \
    && ok "memory API ASan 0 bytes past 256-byte region" || bad "memory API ASan 0 bytes past 256-byte region"

echo "== explicit-codec memory path: plain chosen bytes and vendor fix =="
./evidence-w1/mem-vuln-plain evidence/attack.tga explicit probe > evidence-w1/plain-mem-attack.out 2>&1
if need evidence-w1/plain-mem-attack.out 'rc=0' \
   && need evidence-w1/plain-mem-attack.out 'tail_248_264=aabbccddaabbccddaabbccddaabbccdd'; then
    ok "memory API plain attacker bytes at offsets 256..263"
else
    bad "memory API plain attacker bytes at offsets 256..263"
fi
./evidence-w1/mem-fixed-plain evidence/attack.tga explicit > evidence-w1/plain-mem-fixed.out 2>&1
need evidence-w1/plain-mem-fixed.out 'rc=213' \
    && ok "memory API vendor-fixed v1.0.0 rejects attack (rc=213)" || bad "memory API vendor-fixed v1.0.0 rejects attack"

echo "MEM_PASS=$pass MEM_FAIL=$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
