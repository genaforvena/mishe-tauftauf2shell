#!/bin/sh
# W19 one-command control: the exact W11 wire against the one-line fixed
# decoder in a full gcc -O2 non-PIE build of the pinned tree. The vulnerable
# build reads comm from a wire-chosen address; the fixed build rejects the
# oversized token, forwards a zeroed token and keeps serving a safe NAK.
#   sh lab/frontier/n2n2shell/live/w19_fixed_wire.sh
# Prints "RESULT <n> PASS / <m> FAIL"; rc 0 only when m=0. Loopback only.
set -u
HERE=$(cd "$(dirname "$0")" || exit 1; pwd)
N2N=$(cd "$HERE/.." || exit 1; pwd)
TARBALL=$N2N/provision/n2n-vuln.tar.gz
SENDER=$HERE/w10_large_peer.py
WORK=${REPLAY_LOGDIR:-${TMPDIR:-/tmp}/n2n-w19-replay-$$}
BASE=${PORT_BASE:-19500}
TARGET=0x42f3e8
PASS=0
FAIL=0
mkdir -p "$WORK/src" || exit 1
# The guard rejects the oversized token before decode_buf, but the surviving
# forward encoder still emits the (zeroed) struct: no chosen bytes re-emitted.


check() {
    if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS $1";
    else FAIL=$((FAIL+1)); echo "FAIL $1"; fi
}

(cd "$N2N" && sha256sum -c pins.sha256) >"$WORK/pins.log" 2>&1
check 01-pins-exact "$?"

tar xzf "$TARBALL" -C "$WORK/src" || exit 1
SRC=$WORK/src/n2n-dc7324af16b2ff3e2b22961e7d8dffcb14f3f6ff
[ -d "$SRC" ] || exit 1
python3 - "$SRC/src/wire.c" >"$WORK/guard.log" 2>&1 <<'PY'
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
needle = "    retval += decode_buf(nak->auth.token, nak->auth.token_size, base, rem, idx);\n"
assert s.count(needle) == 1, "unexpected decode_REGISTER_SUPER_NAK body"
guard = ("    if(nak->auth.token_size > N2N_AUTH_MAX_TOKEN_SIZE)\n"
         "        return -1;\n")
open(p, "w", encoding="utf-8").write(s.replace(needle, guard + needle))
print("guard inserted once")
PY
check 02-one-line-guard "$?"
grep -q 'if(nak->auth.token_size > N2N_AUTH_MAX_TOKEN_SIZE)' "$SRC/src/wire.c"
check 03-guard-in-fixed-source "$?"

(cd "$SRC" && sh autogen.sh &&
    CC=gcc CFLAGS="-g -O2 -fno-omit-frame-pointer -no-pie" LDFLAGS="-no-pie" \
    ./configure && make -j4 supernode) >"$WORK/build.log" 2>&1
check 04-fixed-gcc-o2-build "$?"
[ -x "$SRC/supernode" ] || { echo "RESULT $PASS PASS / $FAIL FAIL"; exit 1; }
if grep -q 'N2N_AUTH_MAX_TOKEN_SIZE' "$SRC/src/wire.c"; then
    check 05-fixed-source-in-place 0
else check 05-fixed-source-in-place 1; fi

(cd "$SRC" && timeout 120 ./supernode -f -p 127.0.0.1:$BASE \
    -t $((BASE+1)) -c community.list -F labfed -M) \
    >"$WORK/supernode.log" 2>&1 &
sp=$!
sleep 5
python3 "$SENDER" "$BASE" "$((BASE+10))" 1700 "1682:$TARGET" \
    >"$WORK/attack-sender.log" 2>&1
grep -q 'override token+1682 = e8f3420000000000' "$WORK/attack-sender.log"
check 06-wire-carries-chosen-address "$?"
grep -q 'sent NAK len=1738 token_size=1700' "$WORK/attack-sender.log"
check 07-wire-length "$?"
grep -q 'FORWARDED len=1738 token_len=1700 first=0000000000000000 beyond48=0000000000000000' "$WORK/attack-sender.log"
check 08-fixed-forwards-zero-token "$?"
if grep -q 'REGISTER_SUPER reply len=' "$WORK/attack-sender.log"; then
    check 09-peer-registered 0
else check 09-peer-registered 1; fi
if kill -0 "$sp" 2>/dev/null; then check 10-alive-after-attack 0;
else check 10-alive-after-attack 1; fi
if grep -qi 'SIGSEGV\|AddressSanitizer\|stack-buffer-overflow' "$WORK/supernode.log"; then
    check 11-no-crash-report 1
else check 11-no-crash-report 0; fi

python3 "$SENDER" "$BASE" "$((BASE+12))" 48 \
    >"$WORK/safe-sender.log" 2>&1
grep -q 'REGISTER_SUPER reply len=' "$WORK/safe-sender.log"
check 12-liveness-register-after-attack "$?"
grep -q 'FORWARDED len=86 token_len=48 first=485a4d49485a4d49' "$WORK/safe-sender.log"
check 13-safe-forward-chosen-bytes "$?"
if kill -0 "$sp" 2>/dev/null; then check 14-process-alive 0;
else check 14-process-alive 1; fi

kill "$sp" 2>/dev/null || true
wait "$sp" 2>/dev/null || true
echo "RESULT $PASS PASS / $FAIL FAIL"
echo "RAW $WORK"
[ "$FAIL" -eq 0 ]
