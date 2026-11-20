#!/usr/bin/env bash
# Differential run against stock DragonflyDB images. Host ports are published
# on 127.0.0.1 only; no probe leaves this host.
set -u
VER=${1:-v1.40.1}
RESP=${2:-16379}
MC=${3:-16211}
NAME=dfly-frontier-${VER//./-}
LOGDIR=logs
mkdir -p "$LOGDIR"

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" \
  -p 127.0.0.1:${RESP}:6379 \
  -p 127.0.0.1:${MC}:11211 \
  --entrypoint /usr/local/bin/dragonfly \
  ghcr.io/dragonflydb/dragonfly:${VER} \
  --port 6379 --memcached_port 11211 >/dev/null

for _ in $(seq 1 60); do
  if python3 -c "import socket,sys;s=socket.create_connection(('127.0.0.1',$RESP),0.3);s.close()" 2>/dev/null; then
    break
  fi
  sleep 0.2
done

python3 trigger.py "$RESP" "$MC" > "$LOGDIR/trigger-${VER}.log" 2>&1
RC=$?
sleep 1
docker logs "$NAME" > "$LOGDIR/server-${VER}.log" 2>&1
docker rm -f "$NAME" >/dev/null 2>&1 || true

echo "=== trigger log ($VER), rc=$RC ==="
cat "$LOGDIR/trigger-${VER}.log"
echo "=== server log tail ($VER) ==="
tail -50 "$LOGDIR/server-${VER}.log"
exit "$RC"
