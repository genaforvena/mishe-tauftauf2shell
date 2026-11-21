#!/bin/bash
# Loopback-only: start one ASan kresd build, replay pinned DoQ frames, capture ASan log.
set +e
VER="$1"            # 6.4.0 or 6.4.1
PORT="$2"           # 8853 or 8854
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell
KRESD="$BASE/build/knot-resolver-$VER/asan-build/daemon/kresd"
RUNDIR="$BASE/run/$VER"
LOG="$BASE/harness/kresd-$VER.log"
: > "$LOG"
cd "$RUNDIR" || exit 1
ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:log_path=$BASE/harness/asan-$VER:halt_on_error=0" \
  "$KRESD" -n -c "$RUNDIR/config" "$RUNDIR" >>"$LOG" 2>&1 &
KP=$!
echo "[runner] kresd $VER pid=$KP port=$PORT"
sleep 3
echo "=== startup log ==="
cat "$LOG"
echo "=== replay ==="
"$BASE/poc/venv/bin/python" "$BASE/harness/asan_replay.py" "$PORT" 2>&1
sleep 2
echo "=== kill kresd ==="
kill -9 $KP 2>/dev/null
pkill -9 -f "knot-resolver-$VER/asan-build/daemon/kresd" 2>/dev/null
sleep 1
echo "=== ASan reports (asan-$VER.*) ==="
cat "$BASE"/harness/asan-$VER.* 2>/dev/null
echo "=== tail kresd log ==="
tail -30 "$LOG"
echo "=== END $VER ==="
