#!/bin/sh
# One-command clean-room replay of the n2n2shell live loopback experiment.
# Builds the pinned vulnerable tree three ways (plain, ASan, fixed+ASan),
# starts each supernode on 127.0.0.1, sends the safe (token_size=48) and
# attack (token_size=96) REGISTER_SUPER_NAK datagrams, and checks the
# observed bytes/reports. No external network contact.
#
#   sh lab/frontier/n2n2shell/live/replay-live.sh
#
# Prints "RESULT <n> PASS / <m> FAIL"; rc 0 only when m=0. Raw logs stay in
# a temporary directory reported at the end (set KEEP=1 to retain it).
set -u
HERE=$(cd "$(dirname "$0")" || exit 1; pwd)
N2N=$(cd "$HERE/.." || exit 1; pwd)
SEND=$HERE/send_nak.py
TARBALL=$N2N/provision/n2n-vuln.tar.gz
WORK=${TMPDIR:-/tmp}/n2n2shell-live-replay.$$
BASE=${PORT_BASE:-18700}
PASS=0
FAIL=0

check() {
    if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS-$1";
    else FAIL=$((FAIL+1)); echo "FAIL-$1"; fi
}

cleanup() {
    [ -n "${SN_PID:-}" ] && kill "$SN_PID" 2>/dev/null
    if [ "${KEEP:-0}" = 1 ]; then echo "KEPT $WORK";
    else rm -rf "$WORK"; fi
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$WORK" || exit 1

# 01: pins verify before anything is built.
(cd "$N2N" && sha256sum -c pins.sha256) >"$WORK/pins.out" 2>&1
check 01-pins-exact "$?"

# Build function: plain / asan / fixed. The fixed tree is the vulnerable
# tree plus the single bound from provision/wire-fixed.c, nothing else.
build_tree() {
    name=$1 cc=$2 cflags=$3 ldflags=$4
    d=$WORK/$name
    mkdir -p "$d" || return 1
    tar xzf "$TARBALL" -C "$d" || return 1
    src=$d/n2n-dc7324af16b2ff3e2b22961e7d8dffcb14f3f6ff
    [ -d "$src" ] || return 1
    if [ "$name" = fixed ]; then
        python3 - "$src/src/wire.c" <<'PY'
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
needle = "    retval += decode_buf(nak->auth.token, nak->auth.token_size, base, rem, idx);\n"
assert s.count(needle) == 1, "unexpected decode_REGISTER_SUPER_NAK body"
guard = ("    if(nak->auth.token_size > N2N_AUTH_MAX_TOKEN_SIZE)\n"
         "        return -1;\n")
open(p, "w", encoding="utf-8").write(s.replace(needle, guard + needle))
PY
        [ $? -eq 0 ] || return 1
    fi
    (cd "$src" && sh autogen.sh &&
        CC="$cc" CFLAGS="$cflags" LDFLAGS="$ldflags" ./configure &&
        make -j4 supernode) >"$WORK/build-$name.log" 2>&1
    [ -x "$src/supernode" ] || return 1
    echo "$src"
}

PLAIN=$(build_tree plain gcc "-g -O1 -fno-omit-frame-pointer" "")
check 02-plain-build "$?"
ASAN=$(build_tree asan clang "-fsanitize=address -fno-omit-frame-pointer -g -O1" "-fsanitize=address")
check 03-asan-build "$?"
FIXED=$(build_tree fixed clang "-fsanitize=address -fno-omit-frame-pointer -g -O1" "-fsanitize=address")
check 04-fixed-build "$?"

# run_case <label> <port> <tree> : safe datagram, then attack datagram.
# Leaves the process log at $WORK/<label>.log and sets SN_RC / SN_ALIVE.
run_case() {
    label=$1 port=$2 tree=$3
    : >"$WORK/$label.log"
    ASAN_OPTIONS=detect_leaks=0 "$tree/supernode" -f -v \
        -p "127.0.0.1:$port" -t "$((port+1))" \
        -c "$tree/community.list" -F labfed -M \
        >>"$WORK/$label.log" 2>&1 &
    SN_PID=$!
    sleep 1
    python3 "$SEND" "$port" safe >>"$WORK/$label-sender.log" 2>&1
    sleep 1
    python3 "$SEND" "$port" attack >>"$WORK/$label-sender.log" 2>&1
    sleep 2
    if kill -0 "$SN_PID" 2>/dev/null; then
        SN_ALIVE=1
        kill "$SN_PID" 2>/dev/null
        wait "$SN_PID" 2>/dev/null
        SN_RC=0
    else
        SN_ALIVE=0
        wait "$SN_PID" 2>/dev/null
        SN_RC=$?
    fi
    SN_PID=
}

# Plain build: both datagrams are received; the chosen bytes are written,
# but there is no sanitizer and no abort on this build.
run_case plain "$BASE" "$PLAIN"
grep -q 'Rx REGISTER_SUPER_NAK' "$WORK/plain.log"
check 05-plain-received-nak "$?"
[ "$SN_ALIVE" -eq 1 ]
check 06-plain-survives-attack "$?"

# Vulnerable ASan build: safe clean, attack is the rung-3 stack write with
# the three pinned frames.
run_case vuln-asan "$((BASE+10))" "$ASAN"
grep -q 'Rx REGISTER_SUPER_NAK' "$WORK/vuln-asan.log"
check 07-asan-received-nak "$?"
grep -q 'ERROR: AddressSanitizer: stack-buffer-overflow' "$WORK/vuln-asan.log"
check 08-asan-stack-overflow "$?"
grep -q 'WRITE of size 96' "$WORK/vuln-asan.log"
check 09-asan-write-96 "$?"
grep -q 'decode_buf' "$WORK/vuln-asan.log" &&
    grep -q 'decode_REGISTER_SUPER_NAK' "$WORK/vuln-asan.log" &&
    grep -q 'process_udp' "$WORK/vuln-asan.log"
check 10-asan-three-frames "$?"
[ "$SN_ALIVE" -eq 0 ]
check 11-asan-process-aborted "$?"

# Fixed build on the same no-peer path: bound holds, process stays alive.
run_case fixed-asan "$((BASE+20))" "$FIXED"
grep -q 'Rx REGISTER_SUPER_NAK' "$WORK/fixed-asan.log"
check 12-fixed-received-nak "$?"
if grep -q 'ERROR: AddressSanitizer' "$WORK/fixed-asan.log"; then RC=1; else RC=0; fi
check 13-fixed-no-asan-report "$RC"
[ "$SN_ALIVE" -eq 1 ]
check 14-fixed-survives-attack "$?"

# 15: sender printed the exact chosen pattern and lengths for both cases.
grep -q 'sent safe NAK: len=86 token_size=48 token\[0:4\]=485a4d49' "$WORK/plain-sender.log" &&
    grep -q 'sent attack NAK: len=134 token_size=96 token\[0:4\]=485a4d49' "$WORK/plain-sender.log"
check 15-chosen-wire-input "$?"

echo "RESULT $PASS PASS / $FAIL FAIL"
echo "RAW $WORK"
[ "$FAIL" -eq 0 ]
