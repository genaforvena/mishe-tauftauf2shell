#!/usr/bin/env bash
# W15: valid BBS credentials under a DEFAULT (no SSH_ANYAUTH) loopback config.
# Author evidence only; witness must replay independently. No external probes:
# every connection is to a 127.0.0.1 server started by this script.
set -euo pipefail
cd "$(dirname "$0")/../.."
HERE=$PWD
TREE=$HERE/src-tree
P=$HERE/provision
E=$HERE/real-answer/validuser/evidence
PARENT=42f586d70792e46b4934176976bc7949b312dede
PORT=22229
PASSWORD=LabPass123
DEBS="zip libarchive-dev libnspr4-dev autoconf2.13"
pass=0
fail=0
note() { echo "VALIDUSER $*"; }
expect() {
    local pattern=$1 label=$2
    if grep -q "$pattern" "$E/server.log"; then
        note "PASS $label"; pass=$((pass + 1))
    else
        note "FAIL $label"; fail=$((fail + 1))
    fi
}

mkdir -p "$E" "$P/debs" "$P/local"
command -v sshpass >/dev/null || { echo NO_SSHPASS; exit 1; }
test "$(git -C "$TREE" rev-parse HEAD)" = "$PARENT" || { echo TREE_HEAD_MISMATCH; exit 2; }

# Provision a valid user offline with the pinned tree's own makeuser utility.
# The binary resolves data_dir under ctrl/, hence the ctrl/data -> ../data link.
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
cat > "$TREE/ctrl/sbbs.$(hostname).ini" <<EOF
; W15 lab-only loopback config: default auth (no SSH_ANYAUTH), port $PORT
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
	PidFile = sbbs-w15.pid
	LogFacility = User
	LogIdent = synchronet-w15
	umask = 077
EOF

# Verbatim vulnerable statement plus instrumentation-only probe (no copy logic
# is retyped): the same patch the W5/W7/W9 lanes use.
cleanup_stale
git -C "$TREE" checkout -- src/sbbs3/answer.cpp
(cd "$TREE" && patch -p1 < "$HERE/real-answer/vulnerable-probe.patch") || exit 5
make -C "$TREE/3rdp/build" jslib > "$P/jslib-w15.log" 2>&1 || { echo JSLIB_BUILD_FAILED; exit 6; }
make -C "$TREE/src/sbbs3" FILE_LIBS="$FLIBS" > "$P/build-w15.log" 2>&1 || { echo SBBS_BUILD_FAILED; exit 7; }

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
    wait_port_free || return 1
    (cd "$TREE" && exec env SBBSCTRL="$TREE/ctrl" \
        ./src/sbbs3/gcc.linux.x64.exe.debug/sbbs nd nh nj ne > "$E/server.log" 2>&1) &
    SPID=$!
    for i in $(seq 1 60); do
        grep -q 'SSH Server listening' "$E/server.log" && return 0
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
      TERM="$term" timeout $((secs + 4)) sshpass -p "$PASSWORD" ssh -tt \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=no \
        -o HostKeyAlgorithms=+ssh-rsa -o ConnectTimeout=5 \
        -p "$PORT" lab@127.0.0.1 > "$out" 2>&1 || true
}

CHOSEN="$(printf 'A%.0s' $(seq 1 41))$(printf 'B%.0s' $(seq 1 3))MISHE-OOTAUFTAUF$(printf 'Z%.0s' $(seq 1 4))"
CONTROL="$(printf 'A%.0s' $(seq 1 40))"
test "${#CHOSEN}" -eq 64 || { echo BAD_TERM_LENGTH; exit 8; }

start_server || exit 9
run_case "$CHOSEN" "$E/client-chosen64.log" 10
sleep 4
run_case "$CONTROL" "$E/client-control40.log" 8
stop_server

note "CONFIG_OPTIONS=$(grep 'Options =' "$TREE/ctrl/sbbs.$(hostname).ini")"
note "PROBE_COUNT=$(grep -c 'REAL_ANSWER_PROBE' "$E/server.log" || true)"
note "ANYAUTH_LOG_COUNT=$(grep -c 'SSH_ANYAUTH' "$E/server.log" || true)"
expect 'SSH Server listening' 'server listened on loopback without SSH_ANYAUTH'
expect 'SSH REAL_ANSWER_PROBE sizeof=41 l=64 off41=42 off44=4853494d off48=4f4f2d45' \
    'valid password login: chosen MISH/E-OO reached the copy'
expect 'off52=TAUFTAUF' 'valid password login: TAUFTAUF at wordwrap[0..7]'
expect 'REAL_ANSWER_PROBE sizeof=41 l=40 off41=00 off44=00000000 off48=00000000' \
    '40-byte TERM control clean after valid login'
note "RESULT: PASS=$pass FAIL=$fail"
note "EVIDENCE_DIR=$E"
test "$fail" -eq 0
