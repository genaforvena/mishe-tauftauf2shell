#!/usr/bin/env bash
# Run the extracted stock v1.40.1 binary under host Valgrind, loopback only.
set -u
BIN=deps/dragonfly-v1.40.1
RESP=16479
MC=16411
LOGDIR=logs
mkdir -p "$LOGDIR" /tmp/dfly-vg-data

valgrind --tool=memcheck --num-callers=30 \
  --log-file="$LOGDIR/valgrind-v1.40.1.log" \
  "$BIN" --port "$RESP" --memcached_port "$MC" --dir /tmp/dfly-vg-data --force_epoll \
  --proactor_threads=2 >"$LOGDIR/vg-server-v1.40.1.log" 2>&1 &
PID=$!

ready=0
for _ in $(seq 1 200); do
  if python3 -c "import socket;s=socket.create_connection(('127.0.0.1',$RESP),0.3);s.close()" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 0.3
done
echo "ready=$ready pid=$PID"

python3 trigger.py "$RESP" "$MC" >"$LOGDIR/trigger-vg.log" 2>&1
echo "=== trigger under valgrind ==="
cat "$LOGDIR/trigger-vg.log"

sleep 3
kill -TERM "$PID" 2>/dev/null || true
sleep 2
kill -KILL "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true

echo "=== valgrind report (head) ==="
head -80 "$LOGDIR/valgrind-v1.40.1.log"
echo "=== valgrind ERROR SUMMARY ==="
grep -E 'ERROR SUMMARY|Invalid write|Address .* is|bytes after|definitely lost' "$LOGDIR/valgrind-v1.40.1.log" | head -30 || true
