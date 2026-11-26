#!/bin/sh
# Rebuild pinned libde265 1.0.16/1.0.17 from codeload tarballs and run the
# advisory's standalone public-API decoder PoC against its 254-byte bitstream.
# Read-only provisioning; every decode happens in this local process.
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC=$ROOT/src
OUT=$ROOT/out
EV=$ROOT/evidence
mkdir -p "$SRC" "$OUT" "$EV"

check() {
  expected=$1; file=$2
  actual=$(sha256sum "$file" | cut -d' ' -f1)
  if [ "$actual" != "$expected" ]; then
    echo "PIN_FAIL $file expected=$expected actual=$actual"; exit 1
  fi
}

# Provision, then verify every input byte against the recorded pins.
if [ ! -f "$SRC/libde265-v1.0.16.tar.gz" ]; then
  curl -fsSL -o "$SRC/libde265-v1.0.16.tar.gz" \
    https://codeload.github.com/strukturag/libde265/tar.gz/refs/tags/v1.0.16 || exit 1
fi
if [ ! -f "$SRC/libde265-v1.0.17.tar.gz" ]; then
  curl -fsSL -o "$SRC/libde265-v1.0.17.tar.gz" \
    https://codeload.github.com/strukturag/libde265/tar.gz/refs/tags/v1.0.17 || exit 1
fi
if [ ! -f "$SRC/POC.zip" ]; then
  curl -fsSL -o "$SRC/POC.zip" \
    https://github.com/user-attachments/files/26009899/POC.zip || exit 1
fi
check ed12c931759c1575848832f70db5071a001ac813db4e4f568ee08aef6e234d4e "$SRC/libde265-v1.0.16.tar.gz"
check 3a285024fa135fb962b4554e27ca54d7b0013d7084109a75cc9bef741ae57473 "$SRC/libde265-v1.0.17.tar.gz"
check b3b57b422acf96b9ce8c8d116453bbf330c8414d4d3b4947974e56882f5aa1b2 "$SRC/POC.zip"
mkdir -p "$SRC/poc"
(cd "$SRC/poc" && unzip -oq ../POC.zip)
check 73afafa6dd3a1c8ecf403af746ed0e7e279b35c2ab9f4c5a953626fb5d8efa8b "$SRC/poc/reproducer.bin"
check c5b05a8cf45902c5cf23d112edf0c02c417364fb4cfde06f1d396e4604eb26f2 "$SRC/poc/poc.c"

for tag in 1.0.16 1.0.17; do
  srcdir=$SRC/libde265-$tag
  [ -d "$srcdir" ] || tar xzf "$SRC/libde265-v$tag.tar.gz" -C "$SRC"
done


# Same-size benign input: not an HEVC stream, no SPS change, no write.
python3 -c "open('$SRC/poc/safe.bin','wb').write(bytes(254))"

PASS=0; FAIL=0
for tag in 1.0.16 1.0.17; do
  for spec in clang-asan gcc-asan gcc-plain; do
    cc=gcc; cxx=g++
    case "$spec" in
      clang-asan) cc=clang; cxx=clang++;;
    esac
    if [ "$spec" = gcc-plain ]; then
      flags='-O2 -g -DNDEBUG -fno-omit-frame-pointer'
      ldflags=''
    else
      flags='-fsanitize=address -g -O1 -DNDEBUG -fno-omit-frame-pointer'
      ldflags='-fsanitize=address'
    fi
    d=$OUT/libde265-$tag-$spec
    mkdir -p "$d"
    (cd "$d" && CC=$cc CXX=$cxx cmake "$SRC/libde265-$tag" \
       -DBUILD_SHARED_LIBS=OFF -DENABLE_DECODER=OFF -DENABLE_SDL=OFF \
       -DENABLE_TOOLS=OFF -DCMAKE_BUILD_TYPE=Debug \
       -DCMAKE_C_FLAGS="$flags" -DCMAKE_CXX_FLAGS="$flags" \
       -DCMAKE_EXE_LINKER_FLAGS="$ldflags" > configure.log 2>&1 &&
       cmake --build . -j4 > make.log 2>&1) || {
         echo "BUILD_FAIL $tag $spec"; FAIL=$((FAIL+1)); continue; }
    linkflags=$flags
    case "$spec" in gcc-plain) linkflags='-O2 -g';; esac
    $cc $linkflags "$SRC/poc/poc.c" -I"$SRC/libde265-$tag/libde265" \
      -I"$SRC/libde265-$tag" "$d/libde265/libde265.a" -lstdc++ \
      -o "$d/poc" || { echo "LINK_FAIL $tag $spec"; FAIL=$((FAIL+1)); continue; }

    for input in reproducer.bin safe.bin; do
      out=$EV/$tag-$spec-$input.out
      ("$d/poc" "$SRC/poc/$input" > "$out" 2>&1); rc=$?
      asan=$(grep -c 'AddressSanitizer: heap-buffer-overflow' "$out" || true)
      if [ "$tag" = 1.0.16 ] && [ "$input" = reproducer.bin ] && [ "$spec" != gcc-plain ]; then
        if [ "$asan" -ge 1 ] && grep -q 'WRITE of size 2' "$out" && \
           grep -q 'image.h:741' "$out" && grep -q 'slice.cc:2866' "$out"; then
          echo "PASS $tag $spec $input rc=$rc ASan WRITE-2 image.h:741"; PASS=$((PASS+1))
        else echo "FAIL $tag $spec $input rc=$rc expected verbatim WRITE-2"; FAIL=$((FAIL+1)); fi
      elif [ "$tag" = 1.0.16 ] && [ "$input" = reproducer.bin ]; then
        # Plain build: advisory says the write is silent; do not assert a fault.
        if grep -q 'AddressSanitizer' "$out"; then
          echo "FAIL $tag $spec $input unexpected ASan in plain build"; FAIL=$((FAIL+1))
        else
          echo "PASS $tag $spec $input rc=$rc plain build ran"; PASS=$((PASS+1))
        fi
      else
        # Fixed build, and benign input on the vulnerable build: no ASan report.
        if [ "$asan" = 0 ] && [ "$rc" = 0 ]; then
          echo "PASS $tag $spec $input rc=$rc clean control"; PASS=$((PASS+1))
        else echo "FAIL $tag $spec $input rc=$rc asan=$asan control"; FAIL=$((FAIL+1)); fi
      fi
    done
  done
done
echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = 0 ]
