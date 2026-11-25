#!/bin/sh
# One-shot probe: can curl h2c talk to the real Open5GS NRF on loopback?
set -eu
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
P=$HERE/../local-prefix
export LD_LIBRARY_PATH="$P/usr/lib/x86_64-linux-gnu"
LOG=$HERE/evidence
mkdir -p "$LOG"
: > "$LOG/probe-stdout.log"

"$HERE/../build/bld/src/nrf/open5gs-nrfd" -c "$HERE/nrf.yaml" \
    > "$LOG/probe-stdout.log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT

i=0
while [ "$i" -lt 100 ]; do
    if ss -ltn 2>/dev/null | grep -q ':18777'; then break; fi
    sleep 0.1
    i=$((i + 1))
done
echo "WAIT=$i PID=$pid"

curl -sS --http2-prior-knowledge -o "$LOG/probe-json.body" \
    -w 'JSON code=%{http_code} proto=%{http_version}\n' \
    --max-time 8 -H 'Content-Type: application/json' \
    -d '{}' http://127.0.0.1:18777/nrf-v1/nf-instances || true
echo "BODY=$(head -c 200 "$LOG/probe-json.body" 2>/dev/null || true)"
if kill -0 "$pid" 2>/dev/null; then echo 'NRF=ALIVE'; else echo 'NRF=DEAD'; fi
echo ===LOG===
tail -25 "$LOG/probe-stdout.log"
