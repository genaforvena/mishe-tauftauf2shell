#!/usr/bin/env bash
# Loopback-only differential for CVE-2026-120149. Usage: ./run.sh 17.11|17.12
# Pulls the stock image by tag, pins its digest into logs/, starts one local
# container, replays trigger.sql (upstream regression) against itself via
# postgres_fdw SERVER loopback, and captures psql output + server log.
set -u
VER="${1:?usage: ./run.sh 17.11|17.12}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$HERE/logs"
IMAGE="postgres:${VER}"
NAME="pg2shell-${VER//./-}"
HOSTPORT=55431
if [ "$VER" = "17.12" ]; then HOSTPORT=55432; fi

DIGEST="$(docker image inspect "$IMAGE" --format '{{index .RepoDigests 0}}' 2>/dev/null || true)"
echo "image=$IMAGE digest=$DIGEST hostport=$HOSTPORT" | tee "$HERE/logs/differential-$VER.meta"

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" \
  -e POSTGRES_PASSWORD=pg2shell -e POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
  -p "127.0.0.1:${HOSTPORT}:5432" "$IMAGE" >/dev/null || { echo "run failed"; exit 1; }

for i in $(seq 1 40); do
  if docker exec "$NAME" pg_isready -U postgres -h 127.0.0.1 -p 5432 >/dev/null 2>&1; then break; fi
  sleep 0.5
done

docker cp "$HERE/trigger.sql" "$NAME:/tmp/trigger.sql" >/dev/null
docker exec -e PGPASSWORD=pg2shell "$NAME" psql -U postgres -h 127.0.0.1 -p 5432 \
  -f /tmp/trigger.sql >"$HERE/logs/trigger-$VER.out" 2>&1
RC=$?
echo "psql_rc=$RC" | tee -a "$HERE/logs/differential-$VER.meta"

# Did a backend crash?  The postgres log lives in the container's stderr.
docker logs "$NAME" >"$HERE/logs/server-$VER.log" 2>&1
echo "=== psql output ($VER) ==="
cat "$HERE/logs/trigger-$VER.out"
echo "=== server log signals ($VER) ==="
grep -iE 'segmentation|signal 11|server process|terminated|ERROR|FATAL|PANIC' \
  "$HERE/logs/server-$VER.log" | tail -20 || true
echo "=== container still up? ==="
docker inspect -f '{{.State.Running}}' "$NAME"
