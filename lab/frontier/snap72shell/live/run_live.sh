#!/usr/bin/env bash
# Live loopback experiment: real pinned snap7 client under ASan against a
# plant-started fake S7 responder on 127.0.0.1. Vulnerable, guarded and
# well-behaved-response controls are all exercised.
set -u -o pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/snap7-30f37da3114024a71ba93f7fd855c680b97a406f"
FIXED="$HERE/../src/opReadMultiVars.fixed.issue32.cpp"
OUT="$HERE/evidence"
BIN="$HERE/bin"
mkdir -p "$OUT" "$BIN" "$HERE/patched"
python3 - "$HERE/../src/SHA256SUMS" "$HERE/patched/pinned.sha256" <<'PY'
import sys
mapping = {
    's7_micro_client.cpp.30f37da': 'src/core/s7_micro_client.cpp',
    's7_micro_client.h.30f37da': 'src/core/s7_micro_client.h',
    's7_types.h.30f37da': 'src/core/s7_types.h',
    's7_isotcp.h.30f37da': 'src/core/s7_isotcp.h',
    'opReadMultiVars.fixed.issue32.cpp': '../../src/opReadMultiVars.fixed.issue32.cpp',
}
out = []
for line in open(sys.argv[1]):
    digest, name = line.split()
    if name in mapping:
        out.append('%s  %s\n' % (digest, mapping[name]))
open(sys.argv[2], 'w').writelines(out)
assert len(out) == 5
PY
( cd "$SRC" && sha256sum -c --quiet "$HERE/patched/pinned.sha256" ) || exit 1

python3 - "$SRC/src/core/s7_micro_client.cpp" "$FIXED" "$HERE/patched/s7_micro_client.cpp" <<'PY'
import sys
src, fixed, out = sys.argv[1:4]
raw = open(src, 'rb').read().splitlines(keepends=True)
assert raw[306].startswith(b'int TSnap7MicroClient::opReadMultiVars()'), raw[306][:80]
assert raw[430].rstrip() == b'}', raw[430][:80]
body = [line.encode() + b'\r\n' for line in open(fixed, 'r').read().splitlines()]
patched = raw[:306] + body + raw[431:]
assert b'MaxDest' in b''.join(patched)
open(out, 'wb').write(b''.join(patched))
PY
[ $? -eq 0 ] || exit 1

CXXFLAGS="-std=gnu++11 -g -O0 -fno-omit-frame-pointer -fsanitize=address -I$SRC/src/core -I$SRC/src/sys"
SOURCES="$SRC/src/core/s7_peer.cpp $SRC/src/core/s7_isotcp.cpp $SRC/src/core/s7_text.cpp $SRC/src/sys/snap_msgsock.cpp $SRC/src/sys/snap_sysutils.cpp $SRC/src/sys/snap_threads.cpp"

echo "BUILD vuln"
g++ $CXXFLAGS -o "$BIN/vuln-asan" "$HERE/live_client.cpp" "$SRC/src/core/s7_micro_client.cpp" $SOURCES -lpthread -lrt 2> "$OUT/build-vuln.log" || { cat "$OUT/build-vuln.log"; exit 1; }
echo "BUILD fixed"
g++ $CXXFLAGS -o "$BIN/fixed-asan" "$HERE/live_client.cpp" "$HERE/patched/s7_micro_client.cpp" $SOURCES -lpthread -lrt 2> "$OUT/build-fixed.log" || { cat "$OUT/build-fixed.log"; exit 1; }
echo "BUILD vuln-plain"
g++ -std=gnu++11 -g -O0 -I$SRC/src/core -I$SRC/src/sys -o "$BIN/vuln-plain" "$HERE/live_client.cpp" "$SRC/src/core/s7_micro_client.cpp" $SOURCES -lpthread -lrt 2> "$OUT/build-vuln-plain.log" || { cat "$OUT/build-vuln-plain.log"; exit 1; }

run_case() {
    name=$1
    binary=$2
    mode=$3
    dest_size=${4:-}
    if [ -n "$dest_size" ]; then export LIVE_DEST_SIZE="$dest_size"; else unset LIVE_DEST_SIZE; fi
    rm -f "$HERE/port.txt"
    python3 "$HERE/fake_s7_server.py" "$mode" "$HERE/port.txt" "$OUT/$name.server.log" &
    srv_pid=$!
    for _ in $(seq 1 200); do
        [ -s "$HERE/port.txt" ] && break
        kill -0 "$srv_pid" 2>/dev/null || break
        sleep 0.05
    done
    if [ ! -s "$HERE/port.txt" ]; then
        echo "FAIL $name: server never published a port"
        kill "$srv_pid" 2>/dev/null || true
        return 1
    fi
    port=$(cat "$HERE/port.txt")
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$binary" "$port" > "$OUT/$name.client.log" 2>&1
    client_rc=$?
    wait "$srv_pid" || true
    echo "CASE $name client_rc=$client_rc"
    return 0
}

run_case wire-vuln-attack "$BIN/vuln-asan" attack
run_case wire-fixed-attack "$BIN/fixed-asan" attack
run_case wire-vuln-safe "$BIN/vuln-asan" safe
run_case wire-fixed-safe "$BIN/fixed-asan" safe
run_case wire-vuln-plain-bytes "$BIN/vuln-plain" attack 200000
python3 "$HERE/normalize_live.py" "$OUT" | tee "$OUT/normalized.txt"
printf 'TRACE_SHA256=%s\n' "$(sha256sum "$OUT/normalized.txt" | cut -d' ' -f1)"
