#!/bin/sh
# fontforge2shell W2-W8 real-build replay from a clean source tree.
# Usage: FF2S_TARBALL=/path/to/fontforge-20251009.tar.gz sh replay-real.sh
# No network, no loopback service, no external probe. Builds four local trees.
set -u
cd "$(dirname "$0")" || exit 2
TARBALL=${FF2S_TARBALL:-src/fontforge-20251009.tar.gz}
[ -f "$TARBALL" ] || { echo "missing FF2S_TARBALL: $TARBALL" >&2; exit 2; }
TARBALL=$(readlink -f "$TARBALL")
tar tzf "$TARBALL" >/dev/null 2>&1 || exit 2
[ -f pinned/fix-65e80b5.patch ] || exit 2
[ -d src/fontforge-20251009 ] || mkdir -p src && tar xzf "$TARBALL" -C src
[ -d src/fontforge-fixed ] || {
    cp -a src/fontforge-20251009 src/fontforge-fixed
    ( cd src/fontforge-fixed && patch -p1 < ../../pinned/fix-65e80b5.patch ) || exit 2
}
FLAGS='-DCMAKE_BUILD_TYPE=Debug -DENABLE_GUI=OFF -DENABLE_NATIVE_SCRIPTING=ON -DENABLE_PYTHON_SCRIPTING=OFF -DENABLE_PYTHON_EXTENSION=OFF -DENABLE_DOCS=OFF -DBUILD_SHARED_LIBS=OFF -DENABLE_LIBSPIRO=OFF -DENABLE_LIBGIF=OFF -DENABLE_LIBJPEG=OFF -DENABLE_LIBPNG=OFF -DENABLE_LIBREADLINE=OFF -DENABLE_LIBTIFF=OFF -DENABLE_WOFF2=OFF -DENABLE_HARFBUZZ=OFF'
build() {
    name=$1; tree=$2; san=$3
    [ -d "$name" ] || cmake -S "$tree" -B "$name" $FLAGS -DENABLE_SANITIZER="$san" > "$name-configure.log" 2>&1 || exit 2
    [ -x "$name/bin/fontforge" ] || cmake --build "$name" --target fontforgeexe -j2 > "$name-build.log" 2>&1 || exit 2
}
build build-plain src/fontforge-20251009 none
build build-fixed-plain src/fontforge-fixed none
build build-asan src/fontforge-20251009 address
build build-fixed src/fontforge-fixed address
# Scripts use absolute paths; derive them from THIS tree so a clean archive is self-contained.
printf 'Open("%s/truncated.pcf")\n' "$PWD" > replay-open-path.ff
printf 'Open("%s/complete.pcf")\n' "$PWD" > replay-open-complete.ff
printf 'New()\nImport("%s/size-91.pcf")\nImport("%s/sponge-32.pcf")\n' "$PWD" "$PWD" > replay-size-consumer.ff
for s in open-path open-complete size-consumer; do
    [ -f "$s.ff" ] || cp "replay-$s.ff" "$s.ff"
done
python3 make-size-case.py >/dev/null 2>&1 || exit 2
python3 make-consumer-case.py >/dev/null 2>&1 || exit 2
run() {
    label=$1; shift
    printf '%-38s ' "$label"
    "$@" >/dev/null 2>&1
    printf 'rc=%s\n' "$?"
}
echo "=== W8 real Open() ==="
for b in build-plain build-fixed-plain build-asan build-fixed; do
    run "open-path $b" env ASAN_OPTIONS=detect_leaks=0 "./$b/bin/fontforge" -script replay-open-path.ff
done
for b in build-plain build-asan; do
    run "open-complete $b" env ASAN_OPTIONS=detect_leaks=0 "./$b/bin/fontforge" -script replay-open-complete.ff
done
echo "=== W6 real consumer ==="
for b in build-plain build-fixed-plain build-asan build-fixed; do
    run "size-consumer $b" env ASAN_OPTIONS=detect_leaks=0 "./$b/bin/fontforge" -script replay-size-consumer.ff
done
echo "=== W7 file-chosen consumer ==="
for b in build-plain build-fixed-plain build-asan build-fixed; do
    run "filechoice $b" env ASAN_OPTIONS=detect_leaks=0 "./$b/bin/fontforge" -script import-filechoice.ff
done
echo "=== hashes ==="
sha256sum truncated.pcf complete.pcf size-91.pcf sponge-32.pcf choice-4-var.pcf replay-open-path.ff

echo "=== W11 file-chosen pointer dereference ==="
printf 'New()\nImport("%s/value-atk50.pcf")\nSave("/tmp/ff2s-w11-atk50.sfd")\n' "$PWD" "$PWD" > replay-value-atk50-save.ff
printf 'New()\nImport("%s/value-probe.pcf")\nSave("/tmp/ff2s-w11-probe.sfd")\n' "$PWD" "$PWD" > replay-value-probe-save.ff
printf 'New()\nImport("%s/value-atkceiling.pcf")\nSave("/tmp/ff2s-w11-atkceiling.sfd")\n' "$PWD" "$PWD" > replay-value-atkceiling-save.ff
printf 'set pagination off\nrun -script replay-value-atk50-save.ff\nprintf "pc=%%p\\n", $pc\np/x pt\np/x bfc->bitmap\nbt 4\nquit\n' > replay-gdb-deref.cmd
run "atk50+save build-plain"      env ASAN_OPTIONS=detect_leaks=0 ./build-plain/bin/fontforge -script replay-value-atk50-save.ff
run "probe+save build-plain"      ./build-plain/bin/fontforge -script replay-value-probe-save.ff
run "ceiling+save build-plain"    ./build-plain/bin/fontforge -script replay-value-atkceiling-save.ff
run "atk50+save build-fixed-plain" ./build-fixed-plain/bin/fontforge -script replay-value-atk50-save.ff
run "atk50+save build-asan"       env ASAN_OPTIONS=detect_leaks=0 ./build-asan/bin/fontforge -script replay-value-atk50-save.ff
run "probe+save build-asan"       env ASAN_OPTIONS=detect_leaks=0 ./build-asan/bin/fontforge -script replay-value-probe-save.ff
run "atk50+save build-fixed"      env ASAN_OPTIONS=detect_leaks=0 ./build-fixed/bin/fontforge -script replay-value-atk50-save.ff
gdb -q -batch -x replay-gdb-deref.cmd ./build-plain/bin/fontforge 2>&1 | grep -E 'SIGSEGV|pc=|^[$][12]|sfd.c:1671'
sha256sum value-atk50.pcf value-atkceiling.pcf value-probe.pcf replay-value-atk50-save.ff
