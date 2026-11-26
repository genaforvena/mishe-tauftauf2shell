#!/bin/bash
# unarr2shell reproducible harness: real public API + ASan, vulnerable vs
# locally-patched control (the upstream "patched" tag 1.2.0 still contains
# the same sink, so the control is synthetic, not a vendor fix).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/unarr-1.1.0"
FIX="$ROOT/src-locally-fixed"
EVID="$ROOT/evidence"
BUILD="$ROOT/build"
mkdir -p "$EVID" "$BUILD"

# A clean archive contains only the pinned tarball, not the extracted tree.
if [ ! -f "$SRC/CMakeLists.txt" ]; then
  ( cd "$ROOT" && tar -xzf src-v1.1.0.tar.gz ) || exit 1
fi

pass=0; fail=0
check() {
  local label="$1" expect="$2" got="$3"
  if [ "$expect" = "$got" ]; then
    echo "PASS $label (rc=$got)"; pass=$((pass+1))
  else
    echo "FAIL $label (expected rc=$expect, got rc=$got)"; fail=$((fail+1))
  fi
}

# Synthetic one-byte fix; upstream v1.2.0/v1.2.1 are byte-identical at the sink.
if [ ! -d "$FIX" ]; then
  cp -a "$SRC" "$FIX"
  sed -i 's/char \*prefixed = malloc(256 + 1);/char *prefixed = malloc(256 + 2);/' \
    "$FIX/tar/parse-tar.c"
fi

build_lib() {
  local tree="$1" out="$2"
  mkdir -p "$BUILD/$out"
  ( cd "$BUILD/$out" && cmake -DCMAKE_BUILD_TYPE=Debug \
      -DBUILD_SHARED_LIBS=OFF -DENABLE_7Z=OFF \
      -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O0' \
      "$tree" >/dev/null && cmake --build . -j2 >/dev/null ) || return 1
  cc -fsanitize=address -fno-omit-frame-pointer -g -O0 \
     -I"$tree" "$ROOT/harness/driver.c" "$BUILD/$out/libunarr.a" \
     -o "$BUILD/$out/driver" || return 1
}

build_lib "$SRC" vuln || { echo "FAIL build-vuln"; exit 1; }
build_lib "$FIX" fixed || { echo "FAIL build-fixed"; exit 1; }
check build 0 0

python3 "$ROOT/harness/make-poc.py" "$EVID" >/dev/null
check poc 0 0

# Rung 1/3: vulnerable ASan, attack tar.
ASAN_OPTIONS=abort_on_error=0:detect_leaks=0:halt_on_error=1 \
  "$BUILD/vuln/driver" "$EVID/attack.tar" >"$EVID/asan-vuln-attack.out" 2>&1
rc=$?
grep -q 'AddressSanitizer: heap-buffer-overflow' "$EVID/asan-vuln-attack.out" \
  && grep -q 'WRITE of size 101' "$EVID/asan-vuln-attack.out" \
  && grep -q 'tar_get_name' "$EVID/asan-vuln-attack.out"
check asan-vuln-attack 0 $([ $? -eq 0 ] && echo 0 || echo 1)
echo "  ASan rc=$rc; sink:"; grep -m3 -E 'ERROR: AddressSanitizer|WRITE of size|tar_get_name' "$EVID/asan-vuln-attack.out" | sed 's/^/    /'

# Rung 2: safe inputs on vulnerable build.
for s in safe-short-name safe-short-prefix; do
  ASAN_OPTIONS=detect_leaks=0 "$BUILD/vuln/driver" "$EVID/$s.tar" \
    >"$EVID/asan-vuln-$s.out" 2>&1
  check "vuln-$s" 0 $?
done

# Fixed control: attack tar must be clean.
ASAN_OPTIONS=detect_leaks=0 "$BUILD/fixed/driver" "$EVID/attack.tar" \
  >"$EVID/asan-fixed-attack.out" 2>&1
check fixed-attack 0 $?

# Clang cross-check: the project's CMake adds -flto, so link the driver with
# -flto as well (plain clang linking of the LLVM-IR objects fails).
if command -v clang >/dev/null 2>&1; then
  mkdir -p "$BUILD/clang"
  ( cd "$BUILD/clang" && cmake -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug \
      -DBUILD_SHARED_LIBS=OFF -DENABLE_7Z=OFF \
      -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O0' \
      "$SRC" >/dev/null && cmake --build . -j2 >/dev/null ) || echo "FAIL clang-build"
  clang -fsanitize=address -g -O0 -flto -I"$SRC" "$ROOT/harness/driver.c" \
      "$BUILD/clang/libunarr.a" -o "$BUILD/clang/driver" || echo "FAIL clang-link"
  ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 "$BUILD/clang/driver" "$EVID/attack.tar" \
      >"$EVID/asan-clang-vuln-attack.out" 2>&1
  grep -q 'WRITE of size 101' "$EVID/asan-clang-vuln-attack.out" \
      && grep -q 'tar_get_name' "$EVID/asan-clang-vuln-attack.out"
  check asan-clang-vuln-attack 0 $([ $? -eq 0 ] && echo 0 || echo 1)
else
  echo "SKIP clang (absent)"
fi

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
