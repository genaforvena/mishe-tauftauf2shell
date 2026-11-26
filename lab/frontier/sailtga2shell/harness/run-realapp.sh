#!/usr/bin/env bash
# sailtga2shell w1: exercise two SHIPPED SAIL applications (not a bespoke
# harness) against the 28-byte attack file, using the builds from run-all.sh.
#   - v0.9.10 CLI "sail convert" -> ASan report with convert_impl frame
#   - v1.0.0 "advanced" example -> ASan on v0.9.10, vendor guard on v1.0.0
set -u
cd "$(dirname "$0")/.."
ROOT="$PWD"
mkdir -p evidence-w2

pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
need() { grep -q -- "$2" "$1" 2>/dev/null; }

LIBS_VULN="-Wl,--start-group build-vuln-gcc-asan/src/sail/libsail.a build-vuln-gcc-asan/src/sail-codecs-archive/libsail-codecs.a build-vuln-gcc-asan/src/sail-common/libsail-common.a build-vuln-gcc-asan/src/sail-manip/libsail-manip.a -Wl,--end-group"
LIBS_FIXED="-Wl,--start-group build-fixed-plain/src/sail/libsail.a build-fixed-plain/src/sail-codecs-archive/libsail-codecs.a build-fixed-plain/src/sail-common/libsail-common.a build-fixed-plain/src/sail-manip/libsail-manip.a -Wl,--end-group"
ASAN="-fsanitize=address -fno-omit-frame-pointer -g -O0 -fsanitize=address"

echo "== build shipped applications =="
gcc -fopenmp $ASAN -I sail-0.9.10/src -I build-vuln-gcc-asan/include \
    sail-0.9.10/examples/c/sail/sail.c $LIBS_VULN -lm \
    -o evidence-w2/sail-cli-asan 2> evidence-w2/compile-cli.log \
    && ok "compile v0.9.10 shipped CLI (ASan)" || bad "compile v0.9.10 shipped CLI"
gcc -fopenmp $ASAN -I sail-1.0.0/src -I build-vuln-gcc-asan/include \
    sail-1.0.0/examples/c/advanced.c $LIBS_VULN -lm \
    -o evidence-w2/advanced-vuln-asan 2> evidence-w2/compile-advanced-vuln.log \
    && ok "compile v1.0.0 shipped advanced example vs v0.9.10 libs" || bad "compile advanced/vuln"
gcc -fopenmp -g -O0 -I "$ROOT/stubs" -I sail-1.0.0/src -I build-fixed-plain/include \
    sail-1.0.0/examples/c/advanced.c $LIBS_FIXED -lm \
    -o evidence-w2/advanced-fixed 2> evidence-w2/compile-advanced-fixed.log \
    && ok "compile v1.0.0 shipped advanced example vs fixed libs" || bad "compile advanced/fixed"

echo "== real CLI convert on the attack file =="
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 ./evidence-w2/sail-cli-asan \
    convert evidence/attack.tga evidence-w2/out.tga > evidence-w2/cli-asan-attack.out 2>&1
need evidence-w2/cli-asan-attack.out 'WRITE of size 4' \
    && ok "CLI ASan WRITE of size 4" || bad "CLI ASan WRITE of size 4"
need evidence-w2/cli-asan-attack.out 'tga.c:269' \
    && ok "CLI ASan verbatim tga.c:269" || bad "CLI ASan verbatim tga.c:269"
need evidence-w2/cli-asan-attack.out '0 bytes after 256-byte region' \
    && ok "CLI ASan 0 bytes past 256-byte region" || bad "CLI ASan 0 bytes past 256-byte region"
need evidence-w2/cli-asan-attack.out 'convert_impl sail-0.9.10/examples/c/sail/sail.c:185' \
    && ok "CLI stack shows real convert_impl caller" || bad "CLI stack shows real convert_impl caller"

echo "== shipped advanced example: vulnerable vs vendor-fixed =="
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 ./evidence-w2/advanced-vuln-asan \
    evidence/attack.tga > evidence-w2/advanced-vuln-asan.out 2>&1
need evidence-w2/advanced-vuln-asan.out 'WRITE of size 4' \
    && need evidence-w2/advanced-vuln-asan.out 'tga.c:269' \
    && ok "advanced example reaches sink on v0.9.10" || bad "advanced example reaches sink on v0.9.10"
./evidence-w2/advanced-fixed evidence/attack.tga > evidence-w2/advanced-fixed.out 2>&1
if need evidence-w2/advanced-fixed.out 'SAIL_ERROR_INVALID_IMAGE' \
   && ! need evidence-w2/advanced-fixed.out 'ERROR: AddressSanitizer'; then
    ok "advanced example rejected by vendor-fixed v1.0.0 (guard at tga.c:146)"
else
    bad "advanced example rejected by vendor-fixed v1.0.0"
fi

echo "APP_PASS=$pass APP_FAIL=$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
