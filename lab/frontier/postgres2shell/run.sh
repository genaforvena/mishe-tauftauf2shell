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
case "$VER" in
  17.11) EXPECT_DIGEST='sha256:ff87138949ad9a46f32ff23bd6852b52ce024a13dffe9b4087be98292cdd3b4f' ;;
  17.12) EXPECT_DIGEST='sha256:b60e90042aa6b8dbecd58e224b3e36114dbf8ad754465264c2476ad58a86e45c' ;;
  *) echo "unsupported version: $VER" >&2; exit 2 ;;
esac
NAME="pg2shell-${VER//./-}"
HOSTPORT=55431
if [ "$VER" = "17.12" ]; then HOSTPORT=55432; fi

docker pull -q "$IMAGE" >/dev/null
DIGEST="$(docker image inspect "$IMAGE" --format '{{index .RepoDigests 0}}' 2>/dev/null || true)"
case "$DIGEST" in
  *"$EXPECT_DIGEST") ;;
  *) echo "digest mismatch: image=$IMAGE got=$DIGEST expected=$EXPECT_DIGEST" >&2; exit 2 ;;
esac
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
