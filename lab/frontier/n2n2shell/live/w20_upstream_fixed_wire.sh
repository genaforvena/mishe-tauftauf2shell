#!/bin/sh
# W20 one-command control: W11's exact chosen-pointer wire against the
# pinned UPSTREAM FIXED decoder (wire-fixed.c, commit 854fbbe0) built into
# the pinned vulnerable tree as gcc -O2 non-PIE. Unlike W19, which inserted
# only the NAK guard, this replaces src/wire.c with the whole pinned fixed
# file: five guards (four token_size bounds + one num_sn bound).
#   sh lab/frontier/n2n2shell/live/w20_upstream_fixed_wire.sh
# Prints "RESULT <n> PASS / <m> FAIL"; rc 0 only when m=0. Loopback only.
set -u
HERE=$(cd "$(dirname "$0")" || exit 1; pwd)
N2N=$(cd "$HERE/.." || exit 1; pwd)
TARBALL=$N2N/provision/n2n-vuln.tar.gz
FIXED=$N2N/provision/wire-fixed.c
SENDER=$HERE/w10_large_peer.py
WORK=${REPLAY_LOGDIR:-${TMPDIR:-/tmp}/n2n-w20-replay-$$}
BASE=${PORT_BASE:-19560}
TARGET=0x42f3e8
PASS=0
FAIL=0
mkdir -p "$WORK/src" || exit 1

check() {
    if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS $1";
    else FAIL=$((FAIL+1)); echo "FAIL $1"; fi
}

(cd "$N2N" && sha256sum -c pins.sha256) >"$WORK/pins.log" 2>&1
check 01-pins-exact "$?"

tar xzf "$TARBALL" -C "$WORK/src" || exit 1
SRC=$WORK/src/n2n-dc7324af16b2ff3e2b22961e7d8dffcb14f3f6ff
[ -d "$SRC" ] || exit 1

# The pinned fixed decoder has five guards; W19 had only one (NAK).
guards=$(grep -c 'if(.*token_size > N2N_AUTH_MAX_TOKEN_SIZE)\|if((size_t)reg->num_sn \* REG_SUPER_ACK_PAYLOAD_ENTRY_SIZE > REG_SUPER_ACK_PAYLOAD_SPACE)' "$FIXED")
[ "$guards" -eq 5 ]
check 02-pinned-fixed-has-five-guards "$?"
cp "$FIXED" "$SRC/src/wire.c" || exit 1
cmp -s "$FIXED" "$SRC/src/wire.c"
check 03-exact-fixed-decoder-in-place "$?"
grep -q 'if(nak->auth.token_size > N2N_AUTH_MAX_TOKEN_SIZE)' "$SRC/src/wire.c"
check 04-nak-guard-present "$?"

(cd "$SRC" && sh autogen.sh &&
    CC=gcc CFLAGS="-g -O2 -fno-omit-frame-pointer -no-pie" LDFLAGS="-no-pie" \
    ./configure && make -j4 supernode) >"$WORK/build.log" 2>&1
check 05-fixed-decoder-gcc-o2-build "$?"
[ -x "$SRC/supernode" ] || { echo "RESULT $PASS PASS / $FAIL FAIL"; echo "RAW $WORK"; exit 1; }

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
