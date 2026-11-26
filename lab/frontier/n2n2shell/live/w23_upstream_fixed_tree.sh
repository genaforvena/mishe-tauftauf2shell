#!/bin/sh
# W23 one-command control: W11's exact chosen-pointer wire (token_size=1700,
# token+1682 = 0x42f3e8) against a build of the COMPLETE upstream fixed commit
# tree (854fbbe0), not a patched vulnerable tree. W19/W20 substituted decoder
# files into the vulnerable tree; this closes the remaining UNKNOWN from W22.
#
# The fixed decoder must reject the oversized NAK, so no chosen pointer is
# consumed: the supernode forwards zeroed token bytes and keeps serving.
#   sh lab/frontier/n2n2shell/live/w23_upstream_fixed_tree.sh
# Prints "RESULT <n> PASS / <m> FAIL"; rc 0 only when m=0. Loopback only.
set -u
HERE=$(cd "$(dirname "$0")" || exit 1; pwd)
N2N=$(cd "$HERE/.." || exit 1; pwd)
FIXED_TARBALL=$N2N/provision/n2n-fixed.tar.gz
VULN_TARBALL=$N2N/provision/n2n-vuln.tar.gz
SENDER=$HERE/w10_large_peer.py
EVID=${REPLAY_LOGDIR:-$HERE/evidence}
WORK=${TMPDIR:-/tmp}/n2n2shell-w23.$$
BASE=${PORT_BASE:-20120}
TARGET=0x42f3e8
PASS=0
FAIL=0
mkdir -p "$WORK/src/fixed" "$WORK/src/vuln" "$EVID" || exit 1
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

check() {
    if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS $1";
    else FAIL=$((FAIL+1)); echo "FAIL $1"; fi
}

(cd "$N2N" && sha256sum -c pins.sha256) >"$EVID/w23-pins.log" 2>&1
check 01-pins-exact "$?"

tar xzf "$FIXED_TARBALL" -C "$WORK/src/fixed" || exit 1
tar xzf "$VULN_TARBALL" -C "$WORK/src/vuln" || exit 1
FSRC=$WORK/src/fixed/n2n-854fbbe01bbf131bf4cb88f8450d7084267668e1
VSRC=$WORK/src/vuln/n2n-dc7324af16b2ff3e2b22961e7d8dffcb14f3f6ff
[ -f "$FSRC/src/wire.c" ] && [ -f "$VSRC/src/wire.c" ] || exit 1
cmp -s "$FSRC/src/wire.c" "$N2N/provision/wire-fixed.c"
check 02-fixed-tree-wire-is-pinned-fixed "$?"
cmp -s "$VSRC/src/wire.c" "$N2N/provision/wire-vuln.c"
check 03-vuln-tree-wire-is-pinned-vulnerable "$?"
if cmp -s "$FSRC/src/wire.c" "$VSRC/src/wire.c"; then RC=1; else RC=0; fi
check 04-trees-are-distinct-commits "$?"
grep -q 'if(nak->auth.token_size > N2N_AUTH_MAX_TOKEN_SIZE)' "$FSRC/src/wire.c"
check 05-fixed-tree-has-nak-guard "$?"

# Same toolchain and layout as W11 (clang -O2 non-PIE), but the full tree.
(cd "$FSRC" && sh autogen.sh &&
    CC=clang CFLAGS="-g -O2 -fno-omit-frame-pointer -no-pie" LDFLAGS="-no-pie" \
    ./configure && make -j4 supernode) >"$EVID/w23-fixed-tree-build.log" 2>&1
check 06-fixed-tree-clang-o2-build "$?"
[ -x "$FSRC/supernode" ] || { echo "RESULT $PASS PASS / $FAIL FAIL"; echo "RAW $EVID/w23-*"; exit 1; }
readelf -h "$FSRC/supernode" >"$EVID/w23-readelf.log" 2>&1
grep -q 'Type:.*EXEC' "$EVID/w23-readelf.log"
check 07-non-pie-executable "$?"

(cd "$FSRC" && timeout 120 ./supernode -f -p 127.0.0.1:$BASE \
    -t $((BASE+1)) -c community.list -F labfed -M) \
    >"$EVID/w23-fixed-tree-supernode.log" 2>&1 &
sp=$!
sleep 5
python3 "$SENDER" "$BASE" "$((BASE+10))" 1700 "1682:$TARGET" \
    >"$EVID/w23-attack-sender.log" 2>&1
grep -q 'override token+1682 = e8f3420000000000' "$EVID/w23-attack-sender.log"
check 08-wire-carries-chosen-address "$?"
grep -q 'sent NAK len=1738 token_size=1700' "$EVID/w23-attack-sender.log"
check 09-wire-length "$?"
grep -q 'FORWARDED len=1738 token_len=1700 first=0000000000000000 beyond48=0000000000000000' "$EVID/w23-attack-sender.log"
check 10-fixed-tree-forwards-zero-token "$?"
if grep -q 'REGISTER_SUPER reply len=' "$EVID/w23-attack-sender.log"; then
    check 11-peer-registered 0
else check 11-peer-registered 1; fi
if kill -0 "$sp" 2>/dev/null; then check 12-alive-after-attack 0;
else check 12-alive-after-attack 1; fi
if grep -qi 'SIGSEGV\|AddressSanitizer\|stack-buffer-overflow' "$EVID/w23-fixed-tree-supernode.log"; then
    check 13-no-crash-report 1
else check 13-no-crash-report 0; fi

python3 "$SENDER" "$BASE" "$((BASE+12))" 48 \
    >"$EVID/w23-safe-sender.log" 2>&1
grep -q 'REGISTER_SUPER reply len=' "$EVID/w23-safe-sender.log"
check 14-liveness-register-after-attack "$?"
grep -q 'FORWARDED len=86 token_len=48 first=485a4d49485a4d49' "$EVID/w23-safe-sender.log"
check 15-safe-forward-chosen-bytes "$?"
if kill -0 "$sp" 2>/dev/null; then check 16-process-alive 0;
else check 16-process-alive 1; fi

kill "$sp" 2>/dev/null || true
wait "$sp" 2>/dev/null || true
echo "RESULT $PASS PASS / $FAIL FAIL"
echo "RAW $EVID/w23-*.log"
[ "$FAIL" -eq 0 ]
