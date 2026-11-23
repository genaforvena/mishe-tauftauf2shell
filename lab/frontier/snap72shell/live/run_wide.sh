#!/usr/bin/env bash
# W2: measure peer-chosen byte extent across the 65535-byte live-wire copy.
# Separate from run_live.sh so the W1 normalized trace hash stays stable.
set -u -o pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/snap7-30f37da3114024a71ba93f7fd855c680b97a406f"
OUT="$HERE/evidence/wide"
BIN="$HERE/bin"
mkdir -p "$OUT" "$BIN"

# Same pin check as run_live.sh, narrowed to the blobs this experiment builds.
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

SOURCES="$SRC/src/core/s7_peer.cpp $SRC/src/core/s7_isotcp.cpp $SRC/src/core/s7_text.cpp $SRC/src/sys/snap_msgsock.cpp $SRC/src/sys/snap_sysutils.cpp $SRC/src/sys/snap_threads.cpp"

echo "BUILD wide-plain"
g++ -std=gnu++11 -g -O0 -I$SRC/src/core -I$SRC/src/sys -o "$BIN/wide-plain" \
    "$HERE/wide_client.cpp" "$SRC/src/core/s7_micro_client.cpp" $SOURCES \
    -lpthread -lrt 2> "$OUT/build-wide-plain.log" || { cat "$OUT/build-wide-plain.log"; exit 1; }

echo "BUILD wide-asan"
g++ -std=gnu++11 -g -O0 -fno-omit-frame-pointer -fsanitize=address \
    -I$SRC/src/core -I$SRC/src/sys -o "$BIN/wide-asan" \
    "$HERE/wide_client.cpp" "$SRC/src/core/s7_micro_client.cpp" $SOURCES \
    -lpthread -lrt 2> "$OUT/build-wide-asan.log" || { cat "$OUT/build-wide-asan.log"; exit 1; }

run_wide_case() {
    name=$1
    binary=$2
    rm -f "$HERE/port-wide.txt"
    python3 "$HERE/fake_s7_server.py" wide "$HERE/port-wide.txt" "$OUT/$name.server.log" &
    srv_pid=$!
    for _ in $(seq 1 200); do
        [ -s "$HERE/port-wide.txt" ] && break
        kill -0 "$srv_pid" 2>/dev/null || break
        sleep 0.05
    done
    if [ ! -s "$HERE/port-wide.txt" ]; then
        echo "FAIL $name: server never published a port"
        kill "$srv_pid" 2>/dev/null || true
        return 1
    fi
    port=$(cat "$HERE/port-wide.txt")
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$binary" "$port" > "$OUT/$name.client.log" 2>&1
    client_rc=$?
    wait "$srv_pid" || true
    echo "CASE $name client_rc=$client_rc"
}

run_wide_case wide "$BIN/wide-plain"
run_wide_case wide-asan "$BIN/wide-asan"

python3 - "$OUT" <<'PY' | tee "$OUT/normalized.txt"
import glob, os, re, sys
for path in sorted(glob.glob(os.path.join(sys.argv[1], 'wide.*.log'))):
    name = os.path.basename(path)
    for raw in open(path, errors='replace'):
        line = raw.rstrip('\r\n')
        if not (line.startswith('CLIENT_CONNECT_RC=')
                or line.startswith('CLIENT_READ_BEGIN')
                or line.startswith('CLIENT_READ_RC=')
                or line.startswith('DECLARED_DATA_LENGTH=')
                or line.startswith('SERVER_DONE')
                or 'ERROR: AddressSanitizer' in line
                or 'READ of size' in line
                or 'WRITE of size' in line
                or 'opReadMultiVars()' in line
                or line.startswith('SUMMARY: AddressSanitizer')):
            continue
        line = re.sub(r'==\d+==', '==PID==', line)
        line = re.sub(r'port=\d+', 'port=PORT', line)
        line = re.sub(r'BIND=127\.0\.0\.1:\d+', 'BIND=127.0.0.1:PORT', line)
        line = re.sub(r'ACCEPT from [0-9a-fA-F:.]+:\d+', 'ACCEPT from PEER', line)
        line = re.sub(r'0x[0-9a-fA-F]+', 'ADDR', line)
        print('%s %s' % (name, line))
PY
printf 'WIDE_TRACE_SHA256=%s\n' "$(sha256sum "$OUT/normalized.txt" | cut -d' ' -f1)"
