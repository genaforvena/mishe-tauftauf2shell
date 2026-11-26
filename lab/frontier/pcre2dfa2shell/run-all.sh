#!/bin/sh
# Rebuild pinned PCRE2 10.47/10.48 and run the public-API consumer.
# Provisions tarballs from public codeload URLs (read-only) if absent.
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC=$ROOT/src
OUT=$ROOT/out
mkdir -p "$SRC" "$OUT" "$ROOT/evidence"
PASS=0; FAIL=0

for tag in pcre2-10.47 pcre2-10.48; do
  if [ ! -f "$SRC/$tag.tar.gz" ]; then
    curl -fsSL -o "$SRC/$tag.tar.gz" \
      "https://codeload.github.com/PCRE2Project/pcre2/tar.gz/refs/tags/$tag" || exit 1
  fi
  [ -d "$SRC/$tag" ] || tar xzf "$SRC/$tag.tar.gz" -C "$SRC"
done

for tag in 10.47 10.48; do
  srcdir=$SRC/pcre2-$tag
  [ -d "$srcdir" ] || srcdir=$SRC/pcre2-pcre2-$tag
  for spec in gcc-asan clang-asan gcc-plain; do
    cc=gcc; flags="-fsanitize=address -g -O1 -fno-omit-frame-pointer"
    case "$spec" in
      clang-asan) cc=clang;;
      gcc-plain)  flags="-O2 -g";;
    esac
    d=$OUT/pcre2-$tag-$spec
    mkdir -p "$d"
    (cd "$d" && cmake "$srcdir" -DCMAKE_BUILD_TYPE=Release \
       -DCMAKE_C_COMPILER="$cc" -DCMAKE_C_FLAGS="$flags" \
       -DPCRE2_BUILD_TESTS=OFF -DPCRE2_BUILD_PCRE2GREP=OFF \
       -DPCRE2_SUPPORT_JIT=OFF >configure.log 2>&1 &&
       make -j4 >make.log 2>&1) || { echo "BUILD_FAIL $tag $spec"; FAIL=$((FAIL+1)); continue; }
    $cc $flags -I"$d/interface" "$ROOT/harness/dfa.c" "$d/libpcre2-8.a" \
       -o "$d/dfa" || { echo "LINK_FAIL $tag $spec"; FAIL=$((FAIL+1)); continue; }
    out=$ROOT/evidence/$tag-$spec.out
    ("$d/dfa" > "$out" 2>&1); rc=$?
    if [ "$tag" = 10.47 ]; then
      if grep -q "AddressSanitizer: heap-buffer-overflow" "$out" || [ "$rc" = 139 ]; then
        echo "PASS $tag $spec rc=$rc OOB observed"; PASS=$((PASS+1))
      else echo "FAIL $tag $spec rc=$rc no OOB"; FAIL=$((FAIL+1)); fi
    else
      if grep -q "rc=-63" "$out"; then
        echo "PASS $tag $spec rc=-63 HEAPLIMIT control"; PASS=$((PASS+1))
      else echo "FAIL $tag $spec rc=$rc control"; FAIL=$((FAIL+1)); fi
    fi
  done
done
echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = 0 ]
