#!/bin/bash
# ANALYSIS-ONLY measurement: does HTTP keep-alive on ONE TCP connection pin
# sequential requests to the same Puma worker thread? Decides whether
# "same-thread request pacing" (a named blocker for cross-request heap plants)
# is wire-exposed on a stock Sinatra app. NOT an exploit: the /tid route only
# echoes Thread.current.object_id for measurement; no groom, marker,
# ObjectSpace, mtrace, maps or debugger is used.
#
#   bash lab/repro/ruby2shell-keepalive-thread.sh [port] [tag]
#   KA_THREADS=3:3 bash lab/repro/ruby2shell-keepalive-thread.sh [port] [tag]
set -u
cd "$(dirname "$0")/../.." || exit 1
PORT="${1:-4614}"
TAG="${2:-ka-1}"
EV=lab/build/evidence
RU="$EV/ruby2shell-keepalive-thread-$TAG.ru"
OUT="$EV/ruby2shell-keepalive-thread-$TAG.out"
LOG="$EV/ruby2shell-keepalive-thread-$TAG.log"
mkdir -p "$EV"
export GEM_PATH="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0${GEM_PATH:+:$GEM_PATH}"
RB=lab/build/plain/ruby-3.4.12-plain/bin/ruby
PUMA=lab/build/plain/ruby-3.4.12-plain/bin/puma

cat > "$RU" <<'RUBY'
require 'sinatra'
# Measurement-only route: echo the handling thread identity. No exploit code.
get('/tid') { Thread.current.object_id.to_s }
RUBY
cat > "$RU-puma.ru" <<'RUBY'
require 'sinatra'
get('/tid') { Thread.current.object_id.to_s }
run Sinatra::Application
RUBY

rm -f "$OUT" "$LOG" "$OUT.armA" "$OUT.armB" "$OUT.armC"
if [ -n "${KA_THREADS:-}" ] && [ -x "$PUMA" ]; then
  "$RB" "$PUMA" -t "$KA_THREADS" -b "tcp://127.0.0.1:$PORT" "$PWD/$RU-puma.ru" > "$LOG" 2>&1 &
else
  "$RB" "$RU" -o 127.0.0.1 -p "$PORT" > "$LOG" 2>&1 &
fi
PID=$!
READY=NO
for _ in $(seq 1 300); do
  if curl -s -m 1 "http://127.0.0.1:$PORT/tid" >/dev/null 2>&1; then READY=YES; break; fi
  sleep 0.1
done

# Arm A: five GETs in ONE curl invocation -> one TCP connection (keep-alive).
# curl applies -w once per URL; num_connects=0 on later transfers proves reuse.
A=$(for i in 1 2 3 4 5; do printf 'http://127.0.0.1:%s/tid ' "$PORT"; done)
curl -s -m 10 $A -w '|conn=%{num_connects}\n' > "$OUT.armA"

# Arm B: five GETs in SEPARATE curl invocations -> five TCP connections.
: > "$OUT.armB"
for n in 1 2 3 4 5; do
  curl -s -m 5 "http://127.0.0.1:$PORT/tid" -w '|conn=%{num_connects}\n' >> "$OUT.armB"
done

# Arm C: two CONCURRENT connections (primer + attack shape on Puma's pool).
: > "$OUT.armC"
curl -s -m 5 "http://127.0.0.1:$PORT/tid" -w '|conn=%{num_connects}\n' > "$OUT.armC.c1" &
C1=$!
curl -s -m 5 "http://127.0.0.1:$PORT/tid" -w '|conn=%{num_connects}\n' > "$OUT.armC.c2" &
C2=$!
wait "$C1" "$C2"
cat "$OUT.armC.c1" "$OUT.armC.c2" > "$OUT.armC"

kill "$PID" 2>/dev/null
wait "$PID" 2>/dev/null

python3 - "$TAG" "$OUT" "$READY" <<'PY'
import re, sys
tag, out, ready = sys.argv[1:]

def parse(path):
    rows = []
    for line in open(path, errors='replace'):
        m = re.match(r'\s*(\d+)\s*\|\s*conn=(\d+)\s*$', line)
        if m:
            rows.append((m.group(1), m.group(2)))
    return rows

a = parse(out + '.armA')
b = parse(out + '.armB')
c = parse(out + '.armC')
def tids(rows): return [t for t, _ in rows]
def conns(rows): return [n for _, n in rows]

print(f'== {tag} ready={ready}')
print('  arm A (1 conn, 5 reqs) tids:', tids(a), 'conns:', conns(a))
print('  arm B (5 conns)         tids:', tids(b), 'conns:', conns(b))
print('  arm C (2 concurrent)    tids:', tids(c), 'conns:', conns(c))
reused = len(a) >= 2 and conns(a)[1:] == ['0'] * (len(a) - 1)
same_a = len(a) >= 2 and len(set(tids(a))) == 1
diff_b = len(b) >= 2 and len(set(tids(b))) > 1
diff_c = len(c) >= 2 and len(set(tids(c))) > 1
print('  keep-alive reused connection (num_connects=0 later):', reused)
print('  SAME thread across keep-alive requests:', same_a)
print('  DISTINCT threads across separate connections:', diff_b)
print('  DISTINCT threads across concurrent connections:', diff_c)
print('  VERDICT:',
      'KEEPALIVE-PINS-THREAD (same-thread grooming wire-exposed)' if (reused and same_a)
      else 'KEEPALIVE-DIFFERS (same-thread grooming NOT wire-exposed)')
PY
