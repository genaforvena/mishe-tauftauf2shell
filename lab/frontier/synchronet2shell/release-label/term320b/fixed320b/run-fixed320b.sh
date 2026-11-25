#!/usr/bin/env bash
# W22: shipped 3.20b, same 64-byte wire TERM, vulnerable vs pinned fixed-form
# answer.cpp.  Both builds are real sbbs3; clients only ever hit 127.0.0.1.
# The fixed copy statements come verbatim from harness/fixed.inc via
# patch-fixed.py; no hand-typed copy logic here.
set -euo pipefail
cd "$(dirname "$0")/../../.."
HERE=$PWD
TREE=$HERE/src-tree/320b
P=$HERE/provision
LANE=$HERE/release-label/term320b/fixed320b
E=$LANE/evidence
PARENT=db9c5d6fd37ef74b6e6ca647308d351e656de18d
MIRROR=https://github.com/SynchronetBBS/sbbs.git
DEBS="zip libarchive-dev libnspr4-dev autoconf2.13"
pass=0
fail=0
note() { echo "FIXED_320B $*"; }
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
expect_absent() {
    local file=$1 pattern=$2 label=$3
    if grep -qE "$pattern" "$file"; then
        echo "FAIL $label (unexpected: $pattern in $file)"
        fail=$((fail + 1))
    else
        echo "PASS $label"
        pass=$((pass + 1))
    fi
}

if [ ! -e "$TREE/.git" ]; then
    note "cloning pinned parent $PARENT"
    git clone --no-checkout "$MIRROR" "$TREE"
    git -C "$TREE" checkout --detach "$PARENT"
fi
test "$(git -C "$TREE" rev-parse HEAD)" = "$PARENT" || {
    echo "TREE_HEAD_MISMATCH"; exit 2;
}
mkdir -p "$P/debs" "$P/local" "$E" || exit 2
(cd "$P/debs" && for d in $DEBS; do test -f "${d}_"*.deb || apt-get download "$d"; done)
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
stop_server() {
    [ -n "${SPID:-}" ] && kill -TERM "$SPID" 2>/dev/null || true
    [ -n "${SPID:-}" ] && wait "$SPID" 2>/dev/null || true
    cleanup_stale
    SPID=
}
cleanup_all() {
    stop_server
    git -C "$TREE" checkout -- src/sbbs3/answer.cpp 2>/dev/null || true
}
trap cleanup_all EXIT

HN=$(hostname)
INI="$TREE/ctrl/sbbs.$HN.ini"
write_ini() {
    local port=$1
    cat > "$INI" <<EOF
; W22 lab-only loopback SSH config (gitignored tree)
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
	PidFile = sbbs-w5.pid
	LogFacility = User
	LogIdent = synchronet-w5
	umask = 077
EOF
}
PORT=$((24000 + $$ % 1000))
write_ini "$PORT"

build() {
    cleanup_stale
    make -C "$TREE/3rdp/build" jslib > "$P/jslib-w5.log" 2>&1 || return 1
    make -C "$TREE/src/sbbs3" FILE_LIBS="$FLIBS" > "$P/build-w5.log" 2>&1 || return 1
}
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
wait_port_free() {
    for i in $(seq 1 40); do
        ss -ltn 2>/dev/null | grep -q ":$PORT " || return 0
        cleanup_stale
        sleep 0.5
    done
    echo "PORT_BUSY"; return 1
}
start_server() {
    local log=$1
    wait_port_free || return 1
    (cd "$TREE" && SBBSCTRL="$TREE/ctrl" "$TREE/src/sbbs3/gcc.linux.x64.exe.debug/sbbs" \
        nd nh nj ne > "$log" 2>&1) &
    SPID=$!
    for i in $(seq 1 60); do
        grep -q 'SSH Server listening' "$log" && return 0
        sleep 0.5
    done
    echo "SERVER_START_TIMEOUT"; return 1
}

CHOSEN="$(printf 'A%.0s' $(seq 1 41))$(printf 'B%.0s' $(seq 1 3))MISHE-OOTAUFTAUF$(printf 'Z%.0s' $(seq 1 4))"

# Phase 1: unmodified 3.20b plus instrumentation-only probe; chosen 64-byte TERM.
git -C "$TREE" checkout -- src/sbbs3/answer.cpp
(cd "$TREE" && patch -p1 < "$HERE/release-label/term320b/real320b/probe-320b.patch") || exit 3
build || { echo "BUILD_FAILED_VULN"; exit 4; }
start_server "$E/server-vuln.log"
run_case "$CHOSEN" "$E/client-vuln-chosen64.log" 8
stop_server
expect "$E/server-vuln.log" 'REAL_320B_PROBE sizeof=41 l=64 off41=42 cv=4853494d first=0x465541544f4f2d45 last=0x5a5a5a5a46554154' 'vulnerable 3.20b: chosen pointer pair written by 64-byte TERM'
expect_absent "$E/server-vuln.log" 'Node 1 destructor end' 'vulnerable 3.20b: node thread never reaches destructor end'

# Phase 2: pinned fixed-form hunk, same release, same wire TERM, fresh port.
PORT=$((PORT + 1))
write_ini "$PORT"
git -C "$TREE" checkout -- src/sbbs3/answer.cpp
python3 "$LANE/patch-fixed.py" > "$E/pinned-hunk.log" 2>&1 || { cat "$E/pinned-hunk.log"; exit 5; }
expect "$E/pinned-hunk.log" 'FIXED_HUNK_PINNED_OK' 'fixed copy statements are byte-exact pinned cb6d77dbca hunk'
build || { echo "BUILD_FAILED_FIXED"; exit 6; }
start_server "$E/server-fixed.log"
run_case "$CHOSEN" "$E/client-fixed-chosen64.log" 8
stop_server
expect "$E/server-fixed.log" 'FIXED_320B_PROBE sizeof=41 wire=64 len=40 off41=00 cv=00000000 first=\(nil\) last=\(nil\)' 'fixed 3.20b: 64-byte wire TERM leaves adjacent fields clean'
expect "$E/server-fixed.log" 'Node 1 destructor end' 'fixed 3.20b: node thread completes teardown'

echo "RESULT: PASS=$pass FAIL=$fail"
test "$fail" -eq 0
