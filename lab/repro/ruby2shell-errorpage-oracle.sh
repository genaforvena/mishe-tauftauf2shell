#!/bin/bash
# Analysis-only measurement of a stock Sinatra 500 page as a heap-address
# oracle. NOT an exploit: the app has one plain route that raises on missing
# input and no groom/marker middleware, ObjectSpace, maps or debugger in the
# request path. The /proc/PID/maps read is performed by this SCRIPT after the
# response, only to classify the leaked values; it is not available to a
# remote attacker and does not feed any exploit step.
#
#   bash lab/repro/ruby2shell-errorpage-oracle.sh [port] [tag]
set -u
cd "$(dirname "$0")/../.." || exit 1
PORT="${1:-4609}"
TAG="${2:-oracle-1}"
EV=lab/build/evidence
RU="$EV/ruby2shell-errorpage-oracle-$TAG.ru"
BODY="$EV/ruby2shell-errorpage-oracle-$TAG.html"
MAPS="$EV/ruby2shell-errorpage-oracle-$TAG.maps"
LOG="$EV/ruby2shell-errorpage-oracle-$TAG.log"
mkdir -p "$EV"
export GEM_PATH="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0${GEM_PATH:+:$GEM_PATH}"
RB=lab/build/plain/ruby-3.4.12-plain/bin/ruby

cat > "$RU" <<'RUBY'
require 'sinatra'
set :show_exceptions, :after_handler
# A normal app route: raises KeyError when the required param is absent.
get('/x') { params.fetch('required').to_s }
RUBY

rm -f "$BODY" "$MAPS" "$LOG"
"$RB" "$RU" -o 127.0.0.1 -p "$PORT" > "$LOG" 2>&1 &
PID=$!
READY=NO
for _ in $(seq 1 300); do
  if curl -s -m 1 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    READY=YES
    break
  fi
  sleep 0.1
done
# Reuse one process for three requests to separate boot-stable from
# request-scoped object addresses.
for n in 1 2 3; do
  curl -s -A 'Mozilla/5.0' -H 'Accept: text/html' \
    "http://127.0.0.1:$PORT/x" -o "$BODY.$n" \
    -w "req$n HTTP %{http_code} bytes=%{size_download}\n"
done
[ -r "/proc/$PID/maps" ] && cp "/proc/$PID/maps" "$MAPS"
kill "$PID" 2>/dev/null
wait "$PID" 2>/dev/null

python3 - "$TAG" "$BODY" "$MAPS" "$READY" <<'PY'
import re, sys
from collections import Counter
tag, body, maps_file, ready = sys.argv[1:]
def addrs(path):
    return set(int(x, 16) for x in re.findall(r'0x[0-9a-f]{6,}',
                                              open(path, errors='replace').read()))
sets = [addrs(f'{body}.{i}') for i in (1, 2, 3)]
print(f'== {tag} ready={ready} addresses per request: ' +
      ', '.join(str(len(s)) for s in sets))
print('exact intersection all 3:', len(sets[0] & sets[1] & sets[2]))
print('low-12-bit intersection all 3:',
      len({a & 0xfff for a in sets[0]} &
          {a & 0xfff for a in sets[1]} &
          {a & 0xfff for a in sets[2]}))
ranges = []
try:
    for line in open(maps_file):
        p = line.split()
        lo, hi = (int(x, 16) for x in p[0].split('-'))
        name = p[5] if len(p) > 5 else ''.join(p[5:])
        ranges.append((lo, hi, name))
except OSError:
    pass
def where(a):
    for lo, hi, n in ranges:
        if lo <= a < hi:
            return n
    return 'UNMAPPED'
c = Counter(where(a) for a in sets[0])
for name, n in c.most_common():
    print(f'  {n:3d} -> {name}')
# A pass means the page is a usable oracle (stable in-process set present);
# it does NOT claim glibc-heap or libc-base disclosure.
print('PASS: stable in-process GC-heap address set observed'
      if ready == 'YES' and len(sets[0] & sets[1] & sets[2]) >= 1 else 'FAIL')
PY
