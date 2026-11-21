#!/usr/bin/env bash
# Pillow / libopenjp2 2.5.4 consumer-reachability check for OSV-2025-219.
#
# Two independent demonstrations, local process only, no network probe:
#  (A) The official Pillow 12.2.0 wheel - which bundles libopenjp2 2.5.4 - aborts
#      deterministically when the crafted TLM/SOT codestream is decoded through
#      Image.open().load().
#  (B) Pillow 12.2.0 built against the pinned vulnerable libopenjp2 2.5.4: an
#      ASan-instrumented build observes the exact OOB store inside load(), the
#      plain build faults deterministically, and the fixed pin 91d08b11 is clean.
#
# PyPI fetches below are PROVISIONING ONLY (pinned version + SHA-256), never a
# probe. All decoding happens in this process against local files.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out-pillow"}
OUT=$(mkdir -p "$OUT" && cd "$OUT" && pwd) || exit 2
cd "$HERE" || exit 2

PILLOW_VER=12.2.0
SDIST_SHA=a830b1a40919539d07806aa58e1b114df53ddd43213d9c8b75847eee6c0182b5
WHEEL_SHA=62f5409336adb0663b7caa0da5c7d9e7bdbaae9ce761d34669420c2a801b2780
PAD=$HERE/poc-pad.j2k
ORIG=$HERE/src/poc.j2k

: > "$OUT/results.tmp"
pass=0; fail=0
contains() { case "$2" in *"$1"*) return 0;; *) return 1;; esac; }
check() {
  if [ "$2" = 1 ]; then echo "PASS $1" | tee -a "$OUT/results.tmp"; pass=$((pass+1))
  else echo "FAIL $1" | tee -a "$OUT/results.tmp"; fail=$((fail+1)); fi
}

# --- 1. Provision the exact Pillow sdist and wheel (fetch only) -------------
mkdir -p "$OUT/dl-sdist" "$OUT/dl-wheel"
python3 -m pip download --no-deps --no-binary :all: --dest "$OUT/dl-sdist" \
  "pillow==$PILLOW_VER" > "$OUT/dl-sdist.log" 2>&1
python3 -m pip download --no-deps --only-binary :all: --dest "$OUT/dl-wheel" \
  "pillow==$PILLOW_VER" > "$OUT/dl-wheel.log" 2>&1
SDIST=$(find "$OUT/dl-sdist" -maxdepth 1 -name "pillow-$PILLOW_VER.tar.gz" | head -1)
WHEEL=$(find "$OUT/dl-wheel" -maxdepth 1 -name 'pillow-*.whl' | head -1)
if [ -z "$SDIST" ] || [ -z "$WHEEL" ]; then
  echo "provisioning failed; see $OUT/dl-*.log" >&2; exit 2
fi
sd=$(sha256sum "$SDIST" | cut -d' ' -f1)
wd=$(sha256sum "$WHEEL" | cut -d' ' -f1)
check "pinned Pillow sdist SHA-256 matches" "$([ "$sd" = "$SDIST_SHA" ] && echo 1 || echo 0)"
check "pinned Pillow wheel SHA-256 matches" "$([ "$wd" = "$WHEEL_SHA" ] && echo 1 || echo 0)"
[ "$sd" = "$SDIST_SHA" ] && [ "$wd" = "$WHEEL_SHA" ] || exit 2

mkdir -p "$OUT/sdist" "$OUT/pw-wheel"
tar xzf "$SDIST" -C "$OUT/sdist"
python3 -m pip install --no-deps --target "$OUT/pw-wheel" "$WHEEL" \
  > "$OUT/wheel-install.log" 2>&1
BENIGN=$(find "$OUT/sdist" -name 'test-card-lossless.jp2' | head -1)
[ -f "$BENIGN" ] || { echo "benign test image missing from sdist" >&2; exit 2; }

# --- 2. Demonstration A: the official bundled-lib wheel --------------------
PILROOT="$OUT/pw-wheel" python3 "$HERE/pillow-probe.py" "$BENIGN" \
  > "$OUT/wheel-feature.log" 2>&1
check "official wheel bundles libopenjp2 2.5.4" \
  "$(contains 'PIL_JPG2000 2.5.4' "$(cat "$OUT/wheel-feature.log")" && echo 1 || echo 0)"

PILROOT="$OUT/pw-wheel" python3 "$HERE/pillow-probe.py" "$PAD" \
  > "$OUT/wheel-pad.log" 2>&1; wprc=$?
check "official wheel aborts on padded PoC via Image.open().load() (rc 134)" \
  "$([ "$wprc" = 134 ] && contains 'corrupted size vs. prev_size' "$(cat "$OUT/wheel-pad.log")" && echo 1 || echo 0)"

PILROOT="$OUT/pw-wheel" python3 "$HERE/pillow-probe.py" "$ORIG" \
  > "$OUT/wheel-orig.log" 2>&1; worc=$?
check "official wheel aborts on original public PoC (rc 134)" \
  "$([ "$worc" = 134 ] && contains 'corrupted size vs. prev_size' "$(cat "$OUT/wheel-orig.log")" && echo 1 || echo 0)"

pbrc=0
PILROOT="$OUT/pw-wheel" python3 "$HERE/pillow-probe.py" "$BENIGN" \
  > "$OUT/wheel-benign.log" 2>&1 || pbrc=$?
check "official wheel decodes a benign JPEG 2000 image cleanly (rc 0)" \
  "$([ "$pbrc" = 0 ] && contains 'LOAD_OK' "$(cat "$OUT/wheel-benign.log")" && echo 1 || echo 0)"

# --- 3. Build the three pinned shared libs ----------------------------------
mkdir -p "$OUT/build"
tar xzf "$HERE/src/openjpeg-2.5.4.tar.gz" -C "$OUT/build"
tar xzf "$HERE/src/openjpeg-fixed-91d08b11.tar.gz" -C "$OUT/build"
VLSRC=$(find "$OUT/build" -maxdepth 1 -type d -name 'openjpeg-2.5.4' | head -1)
FLSRC=$(find "$OUT/build" -maxdepth 1 -type d -name 'openjpeg-91d08b11*' | head -1)
[ -d "$VLSRC" ] && [ -d "$FLSRC" ] || { echo "pinned sources missing" >&2; exit 2; }

cmake -S "$VLSRC" -B "$OUT/b-vuln" -DBUILD_SHARED_LIBS=ON -DBUILD_CODEC=OFF \
  -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$OUT/install-vuln" > "$OUT/cmake-vuln.log" 2>&1
cmake --build "$OUT/b-vuln" -j4 > "$OUT/build-vuln.log" 2>&1
cmake --install "$OUT/b-vuln" > "$OUT/install-vuln.log" 2>&1

cmake -S "$FLSRC" -B "$OUT/b-fixed" -DBUILD_SHARED_LIBS=ON -DBUILD_CODEC=OFF \
  -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$OUT/install-fixed" > "$OUT/cmake-fixed.log" 2>&1
cmake --build "$OUT/b-fixed" -j4 > "$OUT/build-fixed.log" 2>&1
cmake --install "$OUT/b-fixed" > "$OUT/install-fixed.log" 2>&1

CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
LDFLAGS="-fsanitize=address" \
cmake -S "$VLSRC" -B "$OUT/b-asan" -DBUILD_SHARED_LIBS=ON -DBUILD_CODEC=OFF \
  -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_INSTALL_PREFIX="$OUT/install-asan" > "$OUT/cmake-asan.log" 2>&1
cmake --build "$OUT/b-asan" -j4 > "$OUT/build-asan.log" 2>&1
cmake --install "$OUT/b-asan" > "$OUT/install-asan.log" 2>&1

check "all three pinned shared libs built" \
  "$([ -f "$OUT/install-vuln/lib/libopenjp2.so.7" ] && \
     [ -f "$OUT/install-fixed/lib/libopenjp2.so.7" ] && \
     [ -f "$OUT/install-asan/lib/libopenjp2.so.7" ] && echo 1 || echo 0)"

# Pillow linked to the pinned vulnerable lib, with an RUNPATH for that lib.
JPEG2K_ROOT="$OUT/install-vuln" CFLAGS="-g -O1 -fno-omit-frame-pointer" \
LDFLAGS="-Wl,-rpath,$OUT/install-vuln/lib" \
python3 -m pip install --no-binary :all: --no-deps --target "$OUT/pw-vuln" "$SDIST" \
  > "$OUT/pw-vuln-build.log" 2>&1
res_vuln=$(ldd "$OUT"/pw-vuln/PIL/_imaging*.so 2>/dev/null)
check "Pillow links the pinned vulnerable libopenjp2.so.7" \
  "$(contains 'install-vuln/lib/libopenjp2.so.7' "$res_vuln" && echo 1 || echo 0)"

# LD_LIBRARY_PATH must override the built-in RUNPATH for the fixed control.
res_fixed=$(LD_LIBRARY_PATH="$OUT/install-fixed/lib" ldd "$OUT"/pw-vuln/PIL/_imaging*.so 2>/dev/null)
check "fixed-pin control resolves the fixed lib, not the vulnerable one" \
  "$(contains 'install-fixed/lib/libopenjp2.so.7' "$res_fixed" && echo 1 || echo 0)"

# --- 4. Demonstration B: exact sink, plain fault, and fixed control ----------
ASAN=$(gcc -print-file-name=libasan.so)
LD_PRELOAD="$ASAN" LD_LIBRARY_PATH="$OUT/install-asan/lib" \
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
PILROOT="$OUT/pw-vuln" python3 "$HERE/pillow-probe.py" "$PAD" \
  > "$OUT/pillow-asan.log" 2>&1
al=$(cat "$OUT/pillow-asan.log")
check "ASan: OOB WRITE of size 8 at pinned j2k.c:5086 inside Image.load()" \
  "$(contains 'WRITE of size 8' "$al" && contains 'j2k.c:5086' "$al" && \
     contains 'Jpeg2KDecode.c:794' "$al" && contains 'decode.c:132' "$al" && echo 1 || echo 0)"
check "ASan: 24-byte tp_index allocated at pinned j2k.c:8939" \
  "$(contains '24-byte region' "$al" && contains 'j2k.c:8939' "$al" && echo 1 || echo 0)"

LD_LIBRARY_PATH="$OUT/install-vuln/lib" PILROOT="$OUT/pw-vuln" \
  python3 "$HERE/pillow-probe.py" "$PAD" > "$OUT/plain-pad.log" 2>&1; pprc=$?
check "plain pinned build faults deterministically on padded PoC" \
  "$([ "$pprc" = 139 ] && echo 1 || echo 0)"

LD_LIBRARY_PATH="$OUT/install-vuln/lib" PILROOT="$OUT/pw-vuln" \
  python3 "$HERE/pillow-probe.py" "$ORIG" > "$OUT/plain-orig.log" 2>&1; porc=$?
check "plain pinned build faults deterministically on original PoC" \
  "$([ "$porc" = 139 ] && echo 1 || echo 0)"

LD_LIBRARY_PATH="$OUT/install-fixed/lib" PILROOT="$OUT/pw-vuln" \
  python3 "$HERE/pillow-probe.py" "$PAD" > "$OUT/fixed-pad.log" 2>&1; fprc=$?
check "fixed pin 91d08b11 decodes padded PoC cleanly in the Pillow process" \
  "$([ "$fprc" = 0 ] && contains 'LOAD_OK' "$(cat "$OUT/fixed-pad.log")" && echo 1 || echo 0)"

LD_LIBRARY_PATH="$OUT/install-vuln/lib" PILROOT="$OUT/pw-vuln" \
  python3 "$HERE/pillow-probe.py" "$BENIGN" > "$OUT/plain-benign.log" 2>&1; bbrc=$?
check "pinned vulnerable build decodes benign image cleanly" \
  "$([ "$bbrc" = 0 ] && contains 'LOAD_OK' "$(cat "$OUT/plain-benign.log")" && echo 1 || echo 0)"

trace=$(grep '^PASS ' "$OUT/results.tmp" | sha256sum | cut -d' ' -f1)
echo "TRACE $trace"
echo "RESULT $pass PASS / $fail FAIL"
[ "$fail" = 0 ]
