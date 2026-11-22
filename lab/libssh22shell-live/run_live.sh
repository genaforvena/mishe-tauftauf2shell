#!/bin/bash
# Live loopback experiment driver. Usage: bash run_live.sh VARIANT MODE SEQNO [PORT]
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
VARIANT="${1:-vuln}"
MODE="${2:-short}"
SEQNO="${3:-3}"
PORT="${4:-22222}"
BIN="$ROOT/client-$VARIANT"

if [ ! -x "$BIN" ]; then
    gcc -fsanitize=address -fno-omit-frame-pointer -g -O1 -I"$ROOT/build-$VARIANT/src" \
        -I"$ROOT/src/libssh2-$( [ "$VARIANT" = vuln ] && echo edec1cce27a309399a9d174b73fef9b997148fbb || echo 42e33d81577ed4b95d4b4f6f845e5ee8efe5eeb4 )/include" \
        -o "$BIN" "$ROOT/client.c" "$ROOT/build-$VARIANT/src/libssh2.a" \
        -lssl -lcrypto -lz 2>&1 || exit 1
fi

python3 "$ROOT/fake_server.py" --port "$PORT" --mode "$MODE" --seqno "$SEQNO" \
    > "$ROOT/server-$VARIANT-$MODE-$SEQNO.log" 2>&1 &
SPID=$!
sleep 0.3
ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 \
    "$BIN" "$PORT" > "$ROOT/client-$VARIANT-$MODE-$SEQNO.log" 2>&1
CPID=$?
wait "$SPID" 2>/dev/null
echo "VARIANT=$VARIANT MODE=$MODE SEQNO=$SEQNO CLIENT_RC=$CPID"
grep -E 'HANDSHAKE_RC|AUTH_LIST|CLIENT_DONE|ERROR: AddressSanitizer|heap-buffer-overflow|transport_fullpacket|SUMMARY' \
    "$ROOT/client-$VARIANT-$MODE-$SEQNO.log" | sed 's/^/  /' | head -20
echo "  server: $(grep 'SEND mode' "$ROOT/server-$VARIANT-$MODE-$SEQNO.log" | tail -1)"
exit "$CPID"
