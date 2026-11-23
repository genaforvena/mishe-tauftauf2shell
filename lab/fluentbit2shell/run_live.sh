#!/usr/bin/env bash
# Live-wire Secure-Forward PONG reproduction. Loopback only.
# Usage: MALICIOUS_EXTRA='--rbp 0 --rop <hex>' run_live.sh <binary> <port> <mode> <tag>

set -u
BIN=$1; PORT=$2; MODE=$3; TAG=$4
HERE=$(cd "$(dirname "$0")" && pwd)
OUT="$HERE/evidence"
mkdir -p "$OUT"
CONF="$OUT/$TAG.conf"
SERVERLOG="$OUT/$TAG.server.log"
VICTIMLOG="$OUT/$TAG.victim.log"

sed "s/@PORT@/$PORT/" "$HERE/victim.conf.in" > "$CONF"

case "$MODE" in
  attack)     EXTRA=() ;;
  authorized) EXTRA=(--authorized) ;;
  short)      EXTRA=(--short) ;;
  *) echo "bad mode" >&2; exit 2 ;;
 esac

if [ -n "${MALICIOUS_EXTRA:-}" ]; then
  read -r -a MOREEXTRA <<< "$MALICIOUS_EXTRA"
  EXTRA+=("${MOREEXTRA[@]}")
fi

 python3 "$HERE/malicious_forward.py" --port "$PORT" "${EXTRA[@]}" > "$SERVERLOG" 2>&1 &

SPID=$!
sleep 0.7

ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:log_path=$OUT/$TAG.asan${ASAN_EXTRA:+:$ASAN_EXTRA}" \
  "$BIN" -c "$CONF" > "$VICTIMLOG" 2>&1 &
VPID=$!

for i in $(seq 1 24); do
  sleep 0.5
  if grep -q 'ERROR: AddressSanitizer\|failed authorization\|SIGSEGV' "$VICTIMLOG" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$VPID" 2>/dev/null; then
    break
  fi
done

if kill -0 "$VPID" 2>/dev/null; then
  kill -TERM "$VPID" 2>/dev/null || true
  sleep 1
  kill -KILL "$VPID" 2>/dev/null || true
fi
wait "$VPID" 2>/dev/null; VRC=$?
kill -TERM "$SPID" 2>/dev/null || true
wait "$SPID" 2>/dev/null || true

echo "===== $TAG (mode=$MODE, binary=$BIN, port=$PORT) ====="
echo "SERVER:"; cat "$SERVERLOG"
echo "VICTIM (filtered):"
grep -E 'AddressSanitizer|WRITE of size|secure_forward_pong|failed authorization|handshake|PONG|HELO|signal|SIGSEGV|ERROR|error' "$VICTIMLOG" | head -40
echo "VICTIM exit rc=$VRC"
echo "ASAN FILES:"; ls -1 "$OUT"/$TAG.asan.* 2>/dev/null || echo "(none)"
echo "ASAN HEAD:"
for f in "$OUT"/$TAG.asan.*; do
  [ -f "$f" ] && sed -n '1,35p' "$f"
done
