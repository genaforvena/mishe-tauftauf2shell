#!/usr/bin/env bash
# W5: two-item live-wire probe of the unvalidated pinned-line-427 offset
# advance. Separate evidence tree; no witness-verified artifact is modified.
set -u -o pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/snap7-30f37da3114024a71ba93f7fd855c680b97a406f"
OUT="$HERE/evidence/multi"
BIN="$HERE/bin"
mkdir -p "$OUT" "$BIN"

( cd "$SRC" && sha256sum -c --quiet "$HERE/patched/pinned.sha256" ) || exit 1

SOURCES="$SRC/src/core/s7_peer.cpp $SRC/src/core/s7_isotcp.cpp $SRC/src/core/s7_text.cpp $SRC/src/sys/snap_msgsock.cpp $SRC/src/sys/snap_sysutils.cpp $SRC/src/sys/snap_threads.cpp"
COMMON="$HERE/multi_client.cpp $SRC/src/core/s7_micro_client.cpp $SOURCES"
INC="-I$SRC/src/core -I$SRC/src/sys"

echo "BUILD multi-plain"
g++ -std=gnu++11 -g -O0 $INC -o "$BIN/multi-plain" $COMMON -lpthread -lrt \
    2> "$OUT/build-multi-plain.log" || { cat "$OUT/build-multi-plain.log"; exit 1; }

echo "BUILD multi-asan"
g++ -std=gnu++11 -g -O0 -fno-omit-frame-pointer -fsanitize=address $INC \
    -o "$BIN/multi-asan" $COMMON -lpthread -lrt \
    2> "$OUT/build-multi-asan.log" || { cat "$OUT/build-multi-asan.log"; exit 1; }

run_case() {
    name=$1
    mode=$2
    binary=$3
    rm -f "$HERE/port-multi.txt"
    python3 "$HERE/fake_s7_server_multi.py" "$mode" "$HERE/port-multi.txt" \
        "$OUT/$name.server.log" &
    srv_pid=$!
    for _ in $(seq 1 200); do
        [ -s "$HERE/port-multi.txt" ] && break
        kill -0 "$srv_pid" 2>/dev/null || break
        sleep 0.05
    done
    if [ ! -s "$HERE/port-multi.txt" ]; then
        echo "FAIL $name: server never published a port"
        kill "$srv_pid" 2>/dev/null || true
        return 1
    fi
    port=$(cat "$HERE/port-multi.txt")
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$binary" "$port" \
        > "$OUT/$name.client.log" 2>&1
    client_rc=$?
    wait "$srv_pid" || true
    echo "CASE $name client_rc=$client_rc"
}

run_case multi-plain multi "$BIN/multi-plain"
run_case multi-asan multi "$BIN/multi-asan"
run_case safe-plain multi-safe "$BIN/multi-plain"
run_case safe-asan multi-safe "$BIN/multi-asan"

python3 - "$OUT" <<'PY' | tee "$OUT/normalized.txt"
import glob, os, re, sys
for path in sorted(glob.glob(os.path.join(sys.argv[1], '*.log'))):
    if os.path.basename(path).startswith('build-'):
        continue
    name = os.path.basename(path)
    for raw in open(path, errors='replace'):
        line = raw.rstrip('\r\n')
        if not (line.startswith('MODE=')
                or line.startswith('ITEM0_DECLARED=')
                or line.startswith('SERVER_DONE')
                or line.startswith('CLIENT_CONNECT_RC=')
                or line.startswith('CLIENT_READ_BEGIN')
                or line.startswith('CLIENT_READ_RC=')
                or 'ERROR: AddressSanitizer' in line
                or 'READ of size' in line
                or 'WRITE of size' in line
                or 'opReadMultiVars()' in line
                or 'PerformOperation()' in line
                or line.startswith('SUMMARY: AddressSanitizer')
                or line.startswith('==') and 'SEGV' in line):
            continue
        line = re.sub(r'==\d+==', '==PID==', line)
        line = re.sub(r'BIND=127\.0\.0\.1:\d+', 'BIND=127.0.0.1:PORT', line)
        line = re.sub(r'0x[0-9a-fA-F]+', 'ADDR', line)
        print('%s %s' % (name, line))
PY
printf 'MULTI_TRACE_SHA256=%s\n' "$(sha256sum "$OUT/normalized.txt" | cut -d' ' -f1)"
