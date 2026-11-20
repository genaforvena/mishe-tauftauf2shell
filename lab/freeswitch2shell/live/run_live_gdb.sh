#!/usr/bin/env bash
# Loopback-only live test under gdb: captures the faulting PC and backtrace
# when the chosen wsh->ssl pointer is dereferenced.
set -u
cd "$(dirname "$0")" || exit 1
BASE=$PWD
CONF=$BASE/run/conf
PREFIX=$BASE/run/install
LOG=$BASE/logs/live_gdb
mkdir -p "$LOG" "$BASE/run/log" "$BASE/run/run" "$BASE/run/db"
export BASE CONF PREFIX LOG

sudo -n --preserve-env=BASE,CONF,PREFIX,LOG unshare -n bash -s <<'EOS'
set -u
BASE="$BASE"; CONF="$CONF"; PREFIX="$PREFIX"; LOG="$LOG"
ip link set lo up
ip route add 127.0.0.0/8 dev lo 2>/dev/null || true
ip -o addr show lo > "$LOG/netns.txt"

gdb -q -batch \
  -ex 'set pagination off' \
  -ex 'set confirm off' \
  -ex 'handle SIGPIPE nostop noprint pass' \
  -ex 'run' \
  -ex 'printf "FAULT_PC=%p\n", $pc' \
  -ex 'info registers rip' \
  -ex 'frame 1' \
  -ex 'p/x wsh->ssl' \
  -ex 'p/x *(unsigned long *)((char *)wsh + 131112)' \
  -ex 'frame 0' \
  -ex 'p/x $rdi' \
  -ex 'bt 18' \
  -ex 'info sharedlibrary mod_xml_rpc' \
  --args "$PREFIX/bin/freeswitch" -c -nf -nonat -nosql \
    -conf "$CONF" -log "$BASE/run/log" -run "$BASE/run/run" \
    -db "$BASE/run/db" -mod "$PREFIX/mod" \
  > "$LOG/gdb.txt" 2>&1 &
GDBPID=$!
echo "GDB_PID=$GDBPID"

READY=0
for i in $(seq 1 60); do
  if ss -ltn 2>/dev/null | grep -q ':18080'; then READY=1; break; fi
  if ! kill -0 "$GDBPID" 2>/dev/null; then break; fi
  sleep 1
done
echo "LISTENER_READY=$READY"
ss -ltn > "$LOG/listen.txt" 2>&1

if [ "$READY" -eq 1 ]; then
  python3 "$BASE/live_client.py" 18080 > "$LOG/client.txt" 2>&1
fi

for i in $(seq 1 30); do
  kill -0 "$GDBPID" 2>/dev/null || break
  sleep 1
done
if kill -0 "$GDBPID" 2>/dev/null; then
  echo "GDB_STILL_RUNNING=1"
  kill -TERM "$GDBPID" 2>/dev/null
  sleep 1
  kill -KILL "$GDBPID" 2>/dev/null
else
  echo "GDB_EXITED=1"
fi
echo '== gdb tail =='
tail -50 "$LOG/gdb.txt"
EOS
