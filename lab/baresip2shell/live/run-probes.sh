#!/bin/bash
# Reproducible debugger probes for the real-libre loopback wire experiment.
# No external network: the client only contacts 127.0.0.1:19015.
set -u
BASE=$(cd "$(dirname "$0")/.." && pwd)
LIVE="$BASE/live"
mkdir -p "$LIVE"

probe() {
	name=$1
	pin=$2
	out="$LIVE/$name.out"
	: > "$out"
	timeout 25 gdb -q -batch -x "$LIVE/$name.gdb" \
		--args "$LIVE/ws_server-$pin" > "$out" 2>&1 &
	pid=$!
	for _ in $(seq 1 50); do
		grep -q '^LISTENING=' "$out" && break
		sleep 0.1
	done
	if ! grep -q '^LISTENING=' "$out"; then
		echo "PROBE=$name NOT_READY"
		kill "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
		return
	fi
	python3 "$LIVE/ws_client.py" crafted > "$LIVE/$name.client.out" 2>&1
	wait "$pid" 2>/dev/null
	echo "PROBE=$name PIN=$pin"
	grep -E '^(STOP|P=|MEM_HEADER_SIZE|MALLOC_PTR|NEXT_CHUNK_AT|SEEN_LEN_HEX|LEFT_BEFORE|DECODE_RETURN|BEFORE_OOB|AFTER_|SLACK_|CHUNK_HEADER|NEXT_CHUNK_EXPECTED|0x555|Program received signal|#[0-5] )' \
		"$out" | head -30 || true
}

probe fixed-enodata fixed
probe plain-layout plain-vuln
probe plain-mem32 plain-vuln
probe plain-crash plain-vuln
