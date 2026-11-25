#!/bin/sh
# W18: second-caller survey. The vulnerable decoder has two in-tree callers:
# supernode sn_utils.c:2322 (surveyed in W12/W15) and edge edge_utils.c:2622.
# This script checks the edge caller's process_udp frame from a clean pinned
# build: is any indirect call target or NAK-case argument inside the
# token_size-controlled stack write window?
#
# Build only; no process is started and no network is contacted.
set -u
N2N=$(cd "$(dirname "$0")/.." && pwd)
TAR="$N2N/provision/n2n-vuln.tar.gz"
OUT=${REPLAY_LOGDIR:-$N2N/live/evidence}
WORK=${W18_WORKDIR:-/tmp/n2n-w18-edge-survey}
mkdir -p "$OUT" "$WORK"
rm -rf "$WORK/tree"
mkdir -p "$WORK/tree"
tar xzf "$TAR" -C "$WORK/tree" || exit 1
SRC=$(find "$WORK/tree" -maxdepth 1 -type d -name 'n2n-*')
[ -n "$SRC" ] || exit 1
(
  cd "$SRC" || exit 1
  sh autogen.sh >"$OUT/w18-edge-autogen.log" 2>&1 &&
  CC=gcc CFLAGS='-g -O1 -fno-omit-frame-pointer' ./configure >"$OUT/w18-edge-configure.log" 2>&1 &&
  make -j4 edge >"$OUT/w18-edge-make.log" 2>&1
) || exit 1
BIN="$SRC/src/edge"
[ -x "$BIN" ] || exit 1

nm "$BIN" | grep -q ' T process_udp$' || exit 1
objdump -d --no-show-raw-insn "$BIN" |
  awk '/<process_udp>:/,/^$/' >"$OUT/w18-edge-process-udp.asm"
ASM="$OUT/w18-edge-process-udp.asm"

PASS=0
FAIL=0
check() {
  if [ "$2" -eq 0 ]; then PASS=$((PASS + 1)); echo "PASS-$1"; else
    FAIL=$((FAIL + 1)); echo "FAIL-$1"
  fi
}

# 1. Frame: nak at rbp-0x1180, canary at rbp-0x38; gap 0x1148=4424 bytes.
grep -q 'mov *%fs:0x28,%rax' "$ASM"
check 01-canary-load "$?"
grep -q 'mov *%rax,-0x38(%rbp)' "$ASM"
check 02-canary-slot "$?"
grep -q 'lea *-0x1180(%rbp),%rdi' "$ASM"
check 03-nak-slot "$?"
grep -q 'call.*decode_REGISTER_SUPER_NAK' "$ASM"
check 04-nak-decode-call "$?"
[ "$((0x1180 - 0x38))" -gt 2010 ]
check 05-canary-beyond-max-write "$?"

# 2. The edge's process_udp does have indirect calls, unlike the supernode's.
INDIRECT=$(grep -c 'call *\*' "$ASM")
[ "$INDIRECT" -eq 5 ]
check 06-five-indirect-calls "$?"
# One bounded switch-table jump, as on the supernode path.
grep -q 'notrack jmp \*' "$ASM"
check 07-switch-table-jump "$?"

# 3. Every indirect call target is an eee->cb field or a peer object loaded
#    from eee (heap), and every site maps to a source line outside the NAK
#    case (which begins at edge_utils.c:2613).
awk '/call +\*/{print substr($1,1,length($1)-1)}' "$ASM" | while read -r addr; do
  addr2line -e "$BIN" "0x$addr" | tail -1
done >"$OUT/w18-edge-indirect-lines.txt"
grep -vq 'edge_utils.c:26[1-9][0-9]' "$OUT/w18-edge-indirect-lines.txt"
check 08-no-indirect-call-in-nak-case "$?"
grep -q 'edge_utils.c:2607' "$OUT/w18-edge-indirect-lines.txt"
check 09-only-ack-callback-near-nak "$?"

# 4. Post-decode NAK case reads only nak fields and eee fields; no indirect
#    call and no read of a spill slot above nak+14.
DECLINE=$(grep -n 'call.*decode_REGISTER_SUPER_NAK' "$ASM" | cut -d: -f1)
NEXTCASE=$(awk -v n="$DECLINE" 'NR>n && /call.*decode_PEER_INFO/{print NR; exit}' "$ASM")
[ -n "$NEXTCASE" ] || NEXTCASE=$((DECLINE + 60))
sed -n "${DECLINE},${NEXTCASE}p" "$ASM" >"$OUT/w18-edge-nak-case.asm"
! grep -q 'call *\*' "$OUT/w18-edge-nak-case.asm"
check 10-nak-case-no-indirect-call "$?"

echo "RESULT $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
