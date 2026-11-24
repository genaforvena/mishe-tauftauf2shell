#!/bin/sh
# Observe the sixth entity's live aliased slot inside a real c-icap server.
# Usage: sh observe.sh BUILD_DIR PORT LABEL MODE [VALUE] [LINE] [MAX_REALLOC]
#   MODE  attack | safe | valid | options   (client.py modes)
#   LINE  source line just after the entity-assignment loop: 513 vulnerable,
#         515 patch-derived fixed. gdb only prints; it writes no memory and
#         forces no call. Raw output: ../evidence/w4-LABEL-{server,client}.out
set -eu
BUILD=$1
PORT=$2
LABEL=$3
MODE=$4
VALUE=${5:-90}
LINE=${6:-513}
REALLOC=${7:-0}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/../evidence
mkdir -p "$OUT"
CFG=/tmp/cicap-w4-$LABEL.conf
GDBCMD=/tmp/cicap-w4-$LABEL.gdb
PIDF=/tmp/cicap-w4-$LABEL.pid
CTL=/tmp/cicap-w4-$LABEL.ctl
rm -f "$PIDF" "$CTL"
cat > "$CFG" <<EOF
PidFile $PIDF
CommandsSocket $CTL
TmpDir /tmp
ServerName cicap-lab-w4-$LABEL
ServerLog /tmp/cicap-w4-$LABEL-server.log
AccessLog /tmp/cicap-w4-$LABEL-access.log
Port 127.0.0.1:$PORT
StartServers 1
MaxServers 1
MaxRequestsReallocateMem $REALLOC
ServicesDir $BUILD/services/echo/.libs
Service echo srv_echo.so
EOF
cat > "$GDBCMD" <<EOF
set pagination off
set confirm off
set breakpoint pending on
handle SIGSEGV nostop noprint pass
handle SIGABRT nostop noprint pass
break request_common.c:$LINE
commands
 silent
 printf "W4_HIT e5=%p t0=%p\\n", req->entities[5], req->trash_entities[0]
 if req->entities[5] != 0
   printf "W4_VAL e5_start=%d e5_type=%d t0_start=%d t0_type=%d alias=%d\\n", req->entities[5]->start, req->entities[5]->type, req->trash_entities[0]->start, req->trash_entities[0]->type, req->entities[5] == req->trash_entities[0]
 end
 continue
end
run
EOF
(ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
    LD_LIBRARY_PATH=$BUILD/.libs \
    gdb -batch -x "$GDBCMD" --args "$BUILD/.libs/c-icap" -N -S -D -f "$CFG" \
    > "$OUT/w4-$LABEL-server.out" 2>&1 &
 GDBPID=$!
 for _ in $(seq 1 100); do
     python3 -c 'import socket,sys; socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2).close()' "$PORT" 2>/dev/null && break
     sleep 0.1
 done
 python3 "$HERE/client.py" "$MODE" "$VALUE" "$PORT" | tee "$OUT/w4-$LABEL-client.out"
 sleep 3
 kill -TERM "$GDBPID" 2>/dev/null || true
 wait "$GDBPID" 2>/dev/null || true)
echo "LABEL=$LABEL MODE=$MODE VALUE=$VALUE LINE=$LINE"
grep -E 'W4_(HIT|VAL)' "$OUT/w4-$LABEL-server.out" || true
if grep -q AddressSanitizer "$OUT/w4-$LABEL-server.out"; then echo ASAN=YES; else echo ASAN=NO; fi
