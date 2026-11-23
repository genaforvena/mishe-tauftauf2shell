#!/bin/bash
# Debugger-assisted readback of the live heap around cmd_qtdpsrc()'s
# xmalloc(slen+1) buffer inside a plant-started, loopback-only pinned
# gdbserver.  gdb breaks at the inlined hex2bin call, at its return and at
# the following source_string allocation, dumps the bytes and auto-continues.
# The client connects only to the 127.0.0.1 port this script starts.
set -u
BIN=${1:?need gdbserver binary}
MODE=${2:-attack}
N=${3:-64}
PORT=${4:-34601}
TAG=${5:-$MODE-$N}
HERE=$(cd "$(dirname "$0")" && pwd)
E="$HERE/evidence"
mkdir -p "$E"
LOG="$E/gdb-heap-$TAG.log"
GDBCMD="$E/gdb-heap-$TAG.cmd"
rm -f "$LOG" "$GDBCMD"

cat >"$GDBCMD" <<'EOF'
set pagination off
set confirm off
set follow-fork-mode parent
set print elements 0
# cmd_qtdpsrc is inlined: +1988 is the call to hex2bin at source line 2547,
# +1998 is just after it, +2010 is the XNEW(source_string) result at 2550.
# $rsi at the call is the xmalloc(slen+1) buffer.
break *handle_tracepoint_general_set+1988
commands
 silent
 set $src = $rsi
 set $cnt = $rdx
 printf "\n=== BP_CALL src=%p count=%ld ===\n", $src, $cnt
 x/6gx $src-16
 x/12gx $src+24
 x/96bx $src
 continue
end
break *handle_tracepoint_general_set+1998
commands
 silent
 printf "\n=== BP_RET src=%p nbytes=%ld ===\n", $src, $rax
 x/6gx $src-16
 x/12gx $src+24
 x/96bx $src
 continue
end
break *handle_tracepoint_general_set+2010
commands
 silent
 printf "\n=== BP_NEWLAST newlast=%p chunkhdr: ===\n", $rax
 x/6gx $rax-16
 continue
end
run
printf "\n=== AFTER_RUN ===\n"
bt 12
info registers rip rdi rsi
x/16i $rip-24
p/x system
EOF

gdb -q -batch -x "$GDBCMD" --args "$BIN" --once --debug=remote \
  "127.0.0.1:$PORT" /bin/true >"$LOG" 2>&1 &
GDB=$!
for _ in $(seq 1 100); do
  if grep -q 'Listening on port' "$LOG" 2>/dev/null; then break; fi
  sleep 0.1
done
python3 "$HERE/live_probe.py" "$PORT" "$MODE" "$N" >"$E/gdb-heap-$TAG.client.out" 2>&1
CLIENT_RC=$?
wait "$GDB"
GDB_RC=$?
echo "CLIENT_RC=$CLIENT_RC GDB_RC=$GDB_RC"
echo "--- client ---"
cat "$E/gdb-heap-$TAG.client.out"
echo "--- gdb markers ---"
grep -aE 'BP_CALL|BP_RET|BP_NEWLAST|AFTER_RUN|Program received signal|exited normally|SIGSEGV|No symbol|optimized out' "$LOG" | head -60
