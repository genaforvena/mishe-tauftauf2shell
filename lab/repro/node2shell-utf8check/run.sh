#!/bin/sh
# node2shell — re-run the closed UTF-8 low-byte-truncation channel check.
#
# Loopback only. Passes an ALT value containing U+0100 (UTF-8 c4 80) as a
# process argument, so Node decodes it to the code point (the harness'
# ALT_HEX path is latin1 and would instead yield U+00C4 U+0080), then
# sends a :authority built from the same pattern.
#
# Expected on vulnerable v24.22.2: server ERR_INVALID_CHAR for the ALT,
# or NGHTTP2_PROTOCOL_ERROR on the stream for a UTF-8 :authority. ASCII
# (--hex 61) completes and prints ALTSVC.
#
# Usage: sh run.sh [hex] [reps]
#   hex  — UTF-8 hex pattern (default c480 = U+0100)
#   reps — authority repetitions (default 520, origin_len 528, off-class)
BASE=$(cd "$(dirname "$0")/../../.." && pwd)
set -u

NODE=${VULN_BIN:-$BASE/lab/node2shell/bin/node-v24.22.2-linux-x64/bin/node}
OUT=${OUT:-$BASE/lab/node2shell/tmp/w24utf8}
HEX=${1:-c480}
REPS=${2:-520}
mkdir -p "$OUT"

# Node emits the UTF-8 bytes; the shell captures them as JS argv, which
# Node decodes back to the code point. argv cannot carry NUL, but c480
# (the hypothesis under test) contains none.
ALT=$("$NODE" -e 'process.stdout.write(Buffer.from(process.argv[1],"hex").toString("utf8"))' "$HEX")

"$NODE" "$BASE/lab/repro/node2shell-rung1-server.js" 0 "$ALT" \
  > "$OUT/server.log" 2>&1 &
SRV=$!
sleep 1
PORT=$(grep -o 'LISTEN [0-9]*' "$OUT/server.log" | awk '{print $2}')
if [ -z "$PORT" ]; then
  echo "server did not listen:"; cat "$OUT/server.log"
  kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; exit 1
fi

"$NODE" "$BASE/lab/repro/node2shell-utf8check/client.js" "$PORT" "$HEX" "$REPS" \
  > "$OUT/client.log" 2>&1
sleep 1
echo "--- client ($OUT/client.log) ---"; cat "$OUT/client.log"
echo "--- server ($OUT/server.log) ---"; cat "$OUT/server.log"
kill "$SRV" 2>/dev/null
wait "$SRV" 2>/dev/null
exit 0
