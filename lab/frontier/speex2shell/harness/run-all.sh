#!/usr/bin/env bash
# Speex CVE-2026-116741 lab checks. Builds real libspeex 1.2.1 from the
# pinned tarball (vulnerable and vendor-fixed), then drives only public APIs.
set -u
cd "$(dirname "$0")/.."

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
need() { grep -q -- "$2" "$1" 2>/dev/null; }

mkdir -p evidence

echo "== pin verification =="
for pair in \
 "src-Speex-1.2.1.tar.gz beaf2642e81a822eaade4d9ebf92e1678f301abfc74a29159c4e721ee70fdce0" \
 "pinned/bits-Speex-1.2.1.c bd36b8081282f5a6e9558b2ed8a0acace0a6c3c976587802b466ff8c628a335a" \
 "pinned/bits-fix-09b569d1.c cc326d16a06cf3758fd8c7182d0bae58d09ecf6947c957c820de1ea800f99461" \
 "harness/driver.c 39032f087b87502bf7ed4864afd501c8c6cc81cc9541a450e4d369ec4607cdd5" \
 "harness/adjacent.c fbb648978898b0b2ce221c4a335bbe73d0da40990746308a86ff940ca29bcfc8"; do
    set -- $pair
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] && ok "pin $1" || bad "pin $1 ($got != $2)"
done

# Vendor fix hunk must be the only functional difference beyond an unrelated
# signed-shift cleanup also present in the fix commit.
if (diff -u pinned/bits-Speex-1.2.1.c pinned/bits-fix-09b569d1.c > evidence/vendor-fix.diff 2>&1 || true) \
   && need evidence/vendor-fix.diff 'nchars=bits->buf_size-(bits->nbBits>>LOG2_BITS_PER_CHAR)-1'; then
    ok "vendor fix hunk present in pinned fixed source"
else
    bad "vendor fix hunk present in pinned fixed source"
fi

echo "== build real libspeex (autotools, pinned tarball) =="
build_tree() {
    dir=$1; cc=$2; cflags=$3; ldflags=$4; fixed=$5; tag=$6
    if [ ! -f "$dir/libspeex/.libs/libspeex.a" ]; then
        rm -rf speex-Speex-1.2.1
        tar -xzf src-Speex-1.2.1.tar.gz || return 1
        mv speex-Speex-1.2.1 "$dir" || return 1
        [ "$fixed" = 1 ] && cp pinned/bits-fix-09b569d1.c "$dir/libspeex/bits.c"
        ( cd "$dir" \
          && NOCONFIGURE=1 ./autogen.sh > "../evidence/$tag-autogen.log" 2>&1 \
          && ./configure CC="$cc" CFLAGS="$cflags" LDFLAGS="$ldflags" \
                 --disable-shared --enable-static > "../evidence/$tag-configure.log" 2>&1 \
          && make -C libspeex -j4 > "../evidence/$tag-make.log" 2>&1 ) || return 1
    fi
    [ -f "$dir/libspeex/.libs/libspeex.a" ]
}
build_tree src-vuln clang '-O0 -g -fno-omit-frame-pointer -fsanitize=address' '-fsanitize=address' 0 asan-vuln \
  && ok "build vulnerable ASan lib" || bad "build vulnerable ASan lib"
build_tree src-fixed clang '-O0 -g -fno-omit-frame-pointer -fsanitize=address' '-fsanitize=address' 1 asan-fixed \
  && ok "build vendor-fixed ASan lib" || bad "build vendor-fixed ASan lib"
build_tree src-plain-vuln gcc '-O0 -g' '' 0 plain-vuln \
  && ok "build vulnerable plain lib" || bad "build vulnerable plain lib"
build_tree src-plain-fixed gcc '-O0 -g' '' 1 plain-fixed \
  && ok "build vendor-fixed plain lib" || bad "build vendor-fixed plain lib"

echo "== compile drivers =="
cflags='-O0 -g -fno-omit-frame-pointer -fsanitize=address'
clang $cflags -I src-vuln/include -I src-vuln harness/driver.c src-vuln/libspeex/.libs/libspeex.a -lm -o evidence/vuln-clang-asan 2> evidence/compile-vuln-clang.log && ok "compile clang ASan driver" || bad "compile clang ASan driver"
gcc   $cflags -I src-vuln/include -I src-vuln harness/driver.c src-vuln/libspeex/.libs/libspeex.a -lm -o evidence/vuln-gcc-asan   2> evidence/compile-vuln-gcc.log   && ok "compile gcc ASan driver"   || bad "compile gcc ASan driver"
clang $cflags -I src-fixed/include -I src-fixed harness/driver.c src-fixed/libspeex/.libs/libspeex.a -lm -o evidence/fixed-clang-asan 2> evidence/compile-fixed-clang.log && ok "compile fixed ASan driver" || bad "compile fixed ASan driver"
gcc -O0 -g -I src-plain-vuln/include -I src-plain-vuln harness/driver.c src-plain-vuln/libspeex/.libs/libspeex.a -lm -o evidence/vuln-plain 2> evidence/compile-vuln-plain.log && ok "compile plain vuln driver" || bad "compile plain vuln driver"
gcc -O0 -g -I src-plain-fixed/include -I src-plain-fixed harness/driver.c src-plain-fixed/libspeex/.libs/libspeex.a -lm -o evidence/fixed-plain 2> evidence/compile-fixed-plain.log && ok "compile plain fixed driver" || bad "compile plain fixed driver"
gcc -O0 -g -I src-plain-vuln/include -I src-plain-vuln harness/adjacent.c src-plain-vuln/libspeex/.libs/libspeex.a -lm -o evidence/adjacent-vuln-plain 2> evidence/compile-adjacent-vuln.log && ok "compile adjacency probe" || bad "compile adjacency probe"
gcc -O0 -g -I src-plain-fixed/include -I src-plain-fixed harness/adjacent.c src-plain-fixed/libspeex/.libs/libspeex.a -lm -o evidence/adjacent-fixed-plain 2> evidence/compile-adjacent-fixed.log && ok "compile fixed adjacency probe" || bad "compile fixed adjacency probe"

echo "== rung 3: ASan-confirmed corruption =="
ASAN_OPTIONS=detect_leaks=0 ./evidence/vuln-gcc-asan attack > evidence/asan-gcc-vuln-attack.out 2>&1
gcc_rc=$?
[ "$gcc_rc" -ne 0 ] && ok "GCC ASan attack rc=$gcc_rc" || bad "GCC ASan attack exited 0"
if need evidence/asan-gcc-vuln-attack.out 'WRITE of size 1' \
   && need evidence/asan-gcc-vuln-attack.out 'bits.c:184' \
   && need evidence/asan-gcc-vuln-attack.out '16-byte region'; then
    ok "GCC ASan WRITE-1 at bits.c:184 past 16-byte region"
else
    bad "GCC ASan WRITE-1 at bits.c:184 past 16-byte region"
fi
ASAN_OPTIONS=detect_leaks=0 ./evidence/vuln-clang-asan attack > evidence/asan-clang-vuln-attack.out 2>&1
clang_rc=$?
[ "$clang_rc" -ne 0 ] && ok "Clang ASan attack rc=$clang_rc" || bad "Clang ASan attack exited 0"
if need evidence/asan-clang-vuln-attack.out 'WRITE of size 1' \
   && need evidence/asan-clang-vuln-attack.out 'bits.c:184' \
   && need evidence/asan-clang-vuln-attack.out '16-byte region'; then
    ok "Clang ASan WRITE-1 at bits.c:184 past 16-byte region"
else
    bad "Clang ASan WRITE-1 at bits.c:184 past 16-byte region"
fi
ASAN_OPTIONS=detect_leaks=0 ./evidence/vuln-clang-asan safe > evidence/asan-clang-vuln-safe.out 2>&1
[ $? -eq 0 ] && need evidence/asan-clang-vuln-safe.out 'nbytes=16' \
  && ok "Clang ASan safe control clean (nbytes=16)" || bad "Clang ASan safe control"
ASAN_OPTIONS=detect_leaks=0 ./evidence/fixed-clang-asan fixed > evidence/asan-fixed-attack.out 2>&1
[ $? -eq 0 ] && need evidence/asan-fixed-attack.out 'nbytes=15' \
  && ok "vendor-fixed ASan attack clean (nbytes=15)" || bad "vendor-fixed ASan attack"

echo "== rung 4: chosen bytes and adjacent live object =="
./evidence/vuln-plain attack > evidence/plain-vuln-attack.out 2>&1
[ $? -eq 0 ] && need evidence/plain-vuln-attack.out 'nbytes=24' \
  && need evidence/plain-vuln-attack.out 'buffer=11121314151617184142434445464748' \
  && ok "plain vulnerable attack: 8 chosen bytes past 16" || bad "plain vulnerable attack"
./evidence/vuln-plain safe > evidence/plain-vuln-safe.out 2>&1
[ $? -eq 0 ] && need evidence/plain-vuln-safe.out 'nbytes=16' \
  && ok "plain safe control clean" || bad "plain safe control"
./evidence/fixed-plain fixed > evidence/plain-fixed-attack.out 2>&1
[ $? -eq 0 ] && need evidence/plain-fixed-attack.out 'nbytes=15' \
  && ok "plain vendor-fixed attack clean" || bad "plain vendor-fixed attack"
./evidence/adjacent-vuln-plain attack > evidence/adjacent-vuln-plain.out 2>&1
[ $? -eq 0 ] && need evidence/adjacent-vuln-plain.out 'delta=32' \
  && need evidence/adjacent-vuln-plain.out 'canary=696a6b6c6d6e6f705a5a5a5a5a5a5a5a' \
  && need evidence/adjacent-vuln-plain.out 'changed=8 chosen=1' \
  && ok "chosen i..p in adjacent live heap object" || bad "adjacent object corruption"
./evidence/adjacent-fixed-plain fixed > evidence/adjacent-fixed-plain.out 2>&1
[ $? -eq 0 ] && need evidence/adjacent-fixed-plain.out 'changed=0 chosen=0' \
  && ok "vendor-fixed adjacency control clean" || bad "vendor-fixed adjacency control"

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ] && exit 0 || exit 1
