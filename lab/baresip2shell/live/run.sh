#!/bin/bash
# Real-libre websock_accept() wire experiment. Loopback only.
# Cases: vulnerable pin + crafted frame, fixed pin + crafted frame,
#        vulnerable pin + short masked frame.
set -u
BASE=$(cd "$(dirname "$0")/.." && pwd)
LIVE="$BASE/live"
mkdir -p "$LIVE"
bash "$LIVE/build.sh" || exit 1

run_case() {
	name=$1
	pin=$2
	mode=$3
	out="$LIVE/$name"
	: > "$out.server.out"
	: > "$out.server.err"
	ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0 \
		"$LIVE/ws_server-$pin" > "$out.server.out" 2> "$out.server.err" &
	pid=$!
	for _ in $(seq 1 50); do
		grep -q '^LISTENING=' "$out.server.out" && break
		sleep 0.1
	done
	if ! grep -q '^LISTENING=' "$out.server.out"; then
		echo "CASE=$name SERVER_NOT_READY"
		kill "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
		return
	fi
	python3 "$LIVE/ws_client.py" "$mode" > "$out.client.out" 2>&1
	sleep 0.5
	if kill -0 "$pid" 2>/dev/null; then
		kill -TERM "$pid" 2>/dev/null
	fi
	wait "$pid" 2>/dev/null
	rc=$?
	echo "CASE=$name PIN=$pin MODE=$mode SERVER_RC=$rc"
	grep -E '^(HTTP_REQ|WEBSOCK_ACCEPT_RC|SRV_RECV|SRV_CLOSE|LISTENING|SERVER_DONE)' \
		"$out.server.out" || true
	grep -E '^(ERROR: AddressSanitizer|READ of size|WRITE of size|SUMMARY: AddressSanitizer|    #[0-9]+ )' \
		"$out.server.err" | head -20 || true
}

run_case crafted-vuln vuln crafted
run_case crafted-fixed fixed crafted
run_case short-vuln vuln short
