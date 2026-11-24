#!/usr/bin/env bash
# W9 bounded experiment: can a custom SSH client send pty-req with the 64-byte
# TERM before authentication on a real sbbs3 build whose config omits
# SSH_ANYAUTH?  This script keeps the negative and its positive control.
# Loopback only; no external target is contacted.  Existing W5/W6/W7 scripts
# are not modified.  Provisioning (pip, .deb extraction) is build-only.
set -euo pipefail
cd "$(dirname "$0")/../.."
HERE=$PWD
TREE=$HERE/src-tree
P=$HERE/provision
E=$HERE/real-answer/noauth/evidence-preauth
PARENT=42f586d70792e46b4934176976bc7949b312dede
PYDIR=$P/local-py
CLIENT=$HERE/real-answer/noauth/preauth_client.py
pass=0
fail=0

note() { echo "PREAUTH $*"; }
expect() {
    if grep -aqF "$2" "$1"; then
        note "PASS $3"
        pass=$((pass + 1))
    else
        note "FAIL $3 (missing: $2)"
        fail=$((fail + 1))
    fi
}
expect_absent() {
    if grep -aqF "$2" "$1"; then
        note "FAIL $3 (unexpected: $2)"
        fail=$((fail + 1))
    else
        note "PASS $3"
        pass=$((pass + 1))
    fi
}

test "$(git -C "$TREE" rev-parse HEAD)" = "$PARENT" || { echo TREE_HEAD_MISMATCH; exit 2; }
mkdir -p "$E" "$P/debs" "$P/local" "$PYDIR"
for f in server-noauth.log server-anyauth.log client-preauth.log client-positive.log; do
    rm -f "$E/$f"
done

# Scripted SSH client, installed into the gitignored lab prefix.
if ! PYTHONPATH="$PYDIR" python3 -c 'import paramiko' >/dev/null 2>&1; then
    python3 -m pip install --quiet --target "$PYDIR" 'paramiko==5.1.0'
fi
PYTHONPATH="$PYDIR" python3 -c 'import paramiko' >/dev/null || { echo PARAMIKO_UNAVAILABLE; exit 3; }

# Build-only toolchain, extracted in the lab (no host package changes).
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
cleanup_stale
git -C "$TREE" checkout -- src/sbbs3/answer.cpp
(cd "$TREE" && patch -p1 < "$HERE/real-answer/vulnerable-probe.patch") || exit 4
make -C "$TREE/3rdp/build" jslib > "$P/jslib-w9.log" 2>&1 || { echo JSLIB_BUILD_FAILED; exit 5; }
make -C "$TREE/src/sbbs3" FILE_LIBS="$FLIBS" > "$P/build-w9.log" 2>&1 || { echo SBBS_BUILD_FAILED; exit 6; }

write_ini() {
    local port=$1 anyauth=$2 opt
    if [ "$anyauth" = yes ]; then
        opt='XTRN_MINIMIZED | ALLOW_SSH | SSH_ANYAUTH | NO_TELNET | NO_HOST_LOOKUP | NO_EVENTS'
    else
        opt='XTRN_MINIMIZED | ALLOW_SSH | NO_TELNET | NO_HOST_LOOKUP | NO_EVENTS'
    fi
    cat > "$TREE/ctrl/sbbs.$(hostname).ini" <<EOF
; W9 lab-only loopback config: anyauth=$anyauth, port=$port
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
	PidFile = sbbs-w9.pid
	LogFacility = User
	LogIdent = synchronet-w9
	umask = 077
EOF
}

SPID=
stop_server() {
    [ -n "$SPID" ] && kill -TERM "$SPID" 2>/dev/null || true
    [ -n "$SPID" ] && wait "$SPID" 2>/dev/null || true
    cleanup_stale
    SPID=
}
trap stop_server EXIT

start_server() {
    local port=$1 log=$2 i
    cleanup_stale
    for i in $(seq 1 40); do
        ss -ltn 2>/dev/null | grep -q ":$port " || break
        sleep 0.5
    done
    (cd "$TREE" && exec env SBBSCTRL="$TREE/ctrl" \
        ./src/sbbs3/gcc.linux.x64.exe.debug/sbbs nd nh nj ne > "$log" 2>&1) &
    SPID=$!
    for i in $(seq 1 60); do
        grep -aq 'SSH Server listening' "$log" && return 0
        sleep 0.5
    done
    echo SERVER_START_TIMEOUT
    return 1
}

run_client() {
    local port=$1 out=$2
    shift 2
    PYTHONPATH="$PYDIR" timeout 30 python3 "$CLIENT" \
        --port "$port" --term "$TERM64" "$@" > "$out" 2>&1 || true
}

CHOSEN="$(printf 'A%.0s' $(seq 1 41))$(printf 'B%.0s' $(seq 1 3))MISHE-OOTAUFTAUF$(printf 'Z%.0s' $(seq 1 4))"
TERM64=$CHOSEN
test "${#TERM64}" -eq 64 || { echo BAD_TERM_LENGTH; exit 7; }

# Case 1: no SSH_ANYAUTH.  Service request first, then a padded channel-open
# so cryptlib's auth-phase length check cannot mask the state-machine check.
write_ini 22228 no
start_server 22228 "$E/server-noauth.log" || exit 8
run_client 22228 "$E/client-preauth.log" --service-request --pad-channel-open
stop_server
expect "$E/server-noauth.log" \
    'Invalid handshake packet SSH_MSG_CHANNEL_OPEN (90), expected SSH_MSG_USERAUTH_REQUEST (50)' \
    'no-ANYAUTH: pinned cryptlib refuses channel-open during the auth phase'
expect_absent "$E/server-noauth.log" 'REAL_ANSWER_PROBE' \
    'no-ANYAUTH: pre-auth pty-req never reaches the verbatim copy'
expect "$E/client-preauth.log" 'service ssh-userauth accepted' \
    'client completed the service request before channel-open'
expect "$E/client-preauth.log" 'padding channel-open 24 -> 26 bytes' \
    'client padding recorded (probe accommodation, not the claim)'
expect "$E/client-preauth.log" 'Unable to open channel' \
    'client observed the channel-open failure'

# Positive control: same client, same TERM, same binary, SSH_ANYAUTH present,
# with the ordinary none-auth request before channel-open (the W5/W6 order).
write_ini 22229 yes
start_server 22229 "$E/server-anyauth.log" || exit 9
run_client 22229 "$E/client-positive.log" --service-request --auth-none-before-pty
stop_server
expect "$E/server-anyauth.log" 'SSH_ANYAUTH allowed with no credential' \
    'positive control: none-auth accepted before channel-open'
expect "$E/server-anyauth.log" \
    'REAL_ANSWER_PROBE sizeof=41 l=64 off41=42 off44=4853494d off48=4f4f2d45 off52=TAUFTAUF' \
    'ANYAUTH: same client sends the chosen TERM to the real answer() copy'
expect "$E/client-positive.log" 'pty-req sent term_len=64' \
    'positive control sent the same 64-byte TERM'
expect "$E/client-positive.log" 'done' 'positive control completed'

note "PREAUTH_PROBE_COUNT=$(grep -ac REAL_ANSWER_PROBE "$E/server-noauth.log" || true)"
note "ANYAUTH_PROBE_COUNT=$(grep -ac REAL_ANSWER_PROBE "$E/server-anyauth.log" || true)"
note "RESULT: PASS=$pass FAIL=$fail"
test "$fail" -eq 0
