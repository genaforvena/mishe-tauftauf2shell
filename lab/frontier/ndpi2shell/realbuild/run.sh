#!/bin/sh
# ndpi2shell W162 — reproducible probe against the REAL pinned nDPI library.
# Run from lab/frontier/ndpi2shell/realbuild.
#
# Provisioning (allowed, no external probes): fetch the pinned vulnerable
# commit tree and build it with ASan. build-* is gitignored by the upstream
# tree's own .gitignore, so none of this is committed.
set -u
HERE=$(pwd)
ROOT=$(cd .. && pwd)
TREE="$ROOT/src/ndpi-full-vuln"
PIN=94e82c1de12323d992895830231865736a8abf2c
PASS=0
FAIL=0
check() {
  if [ "$1" = 0 ]; then PASS=$((PASS+1)); echo "PASS $2";
  else FAIL=$((FAIL+1)); echo "FAIL $2"; fi
}

if [ ! -f "$TREE/build-asan/src/lib/libndpi.a" ]; then
  echo "== provisioning pinned tree =="
  mkdir -p "$ROOT/src"
  curl -sSL -o /tmp/ndpi-vuln.tar.gz \
    "https://codeload.github.com/ntop/nDPI/tar.gz/${PIN}%5E" || exit 2
  mkdir -p "$TREE"
  tar -xzf /tmp/ndpi-vuln.tar.gz -C "$TREE" --strip-components=1 || exit 2
  (cd "$TREE" && ./autogen.sh >/dev/null 2>&1) || exit 2
  mkdir -p "$TREE/build-asan"
  (cd "$TREE/build-asan" && \
    CC=clang CFLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O1' \
    LDFLAGS='-fsanitize=address' ../configure --disable-shared --enable-static \
    >/dev/null 2>&1 && make -j4 >/dev/null 2>&1) || exit 2
fi

sha256sum "$TREE/src/lib/ndpi_serializer.c" | grep -q 4840fb417e420f3821746635f72ad2755d9f802a6ceb041450efb8efe9779ad5
check $? "pinned serializer matches 4840fb41...9ad5"

B="$TREE/build-asan"
clang -fsanitize=address -fno-omit-frame-pointer -g -O1 \
  -I"$B/src/include" -I"$TREE/src/include" driver.c \
  "$B/src/lib/libndpi.a" -lm -lpthread -lpcap -o driver-asan || exit 2
check 0 "driver linked against real libndpi.a"

echo "== direct public API (exact-size 8-byte buffer) =="
ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 ./driver-asan direct > direct.out 2>&1
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' direct.out &&
grep -q 'ndpi_serializer.c:107:18 in ndpi_json_string_escape' direct.out
check $? "direct API ASan WRITE at pinned :107"

echo "== real serializer VALUE path (145 crafted cases) =="
ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 ./driver-asan real > real.out 2>&1
grep -q 'ERROR: AddressSanitizer' real.out
if [ $? -ne 0 ]; then check 0 "VALUE path: 0 ASan reports"; else check 1 "VALUE path: 0 ASan reports"; fi
grep -q '^DONE mode=real' real.out
check $? "VALUE path completed"

echo "== real serializer KEY path (weak-headroom callers) =="
for w in 0 1 2; do
  ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 ./driver-asan weakone 128 256 $w \
    > "one-$w-128.out" 2>&1
  grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "one-$w-128.out" &&
  grep -q 'ndpi_serializer.c:107:18 in ndpi_json_string_escape' "one-$w-128.out" &&
  grep -q 'in ndpi_serialize_' "one-$w-128.out"
  check $? "key path caller $w: real-caller ASan WRITE at :107"
done
ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 ./driver-asan weakone 0 256 0 \
  > one-0-16.out 2>&1
grep -q 'ERROR: AddressSanitizer' one-0-16.out
if [ $? -ne 0 ]; then check 0 "short key (klen=16) clean control"; else check 1 "short key (klen=16) clean control"; fi

echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
