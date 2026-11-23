#!/usr/bin/env bash
# Post-overflow caller fate probe: plain pinned client, live wire attack,
# several destination sizes. Records whether the unvalidated 65535-byte copy
# reaches the caller's delete[]/free() or faults inside memcpy first.
# Writes only to evidence/freeprobe/ and its own ignored binary; every
# witness-verified artifact is left untouched.
set -u -o pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/snap7-30f37da3114024a71ba93f7fd855c680b97a406f"
OUT="$HERE/evidence/freeprobe"
BIN="$HERE/bin"
mkdir -p "$OUT" "$BIN" "$HERE/patched"

python3 - "$HERE/../src/SHA256SUMS" "$HERE/patched/pinned.sha256" <<'PY'
import sys
mapping = {
    's7_micro_client.cpp.30f37da': 'src/core/s7_micro_client.cpp',
    's7_micro_client.h.30f37da': 'src/core/s7_micro_client.h',
    's7_types.h.30f37da': 'src/core/s7_types.h',
    's7_isotcp.h.30f37da': 'src/core/s7_isotcp.h',
}
out = []
for line in open(sys.argv[1]):
    digest, name = line.split()
    if name in mapping:
        out.append('%s  %s\n' % (digest, mapping[name]))
open(sys.argv[2], 'w').writelines(out)
assert len(out) == 4
PY
( cd "$SRC" && sha256sum -c --quiet "$HERE/patched/pinned.sha256" ) || exit 1

g++ -std=gnu++11 -g -O0 -I"$SRC/src/core" -I"$SRC/src/sys" \
    -o "$BIN/freeprobe-plain" "$HERE/live_client.cpp" \
    "$SRC/src/core/s7_micro_client.cpp" "$SRC/src/core/s7_peer.cpp" \
    "$SRC/src/core/s7_isotcp.cpp" "$SRC/src/core/s7_text.cpp" \
    "$SRC/src/sys/snap_msgsock.cpp" "$SRC/src/sys/snap_sysutils.cpp" \
    "$SRC/src/sys/snap_threads.cpp" -lpthread -lrt 2> "$OUT/build.log" || {
    cat "$OUT/build.log"; exit 1; }

run_case() {
    size=$1
    rm -f "$HERE/port.txt"
    python3 "$HERE/fake_s7_server.py" attack "$HERE/port.txt" \
        "$OUT/sweep-$size-server.log" &
    srv=$!
    for _ in $(seq 1 200); do
        [ -s "$HERE/port.txt" ] && break
        kill -0 "$srv" 2>/dev/null || break
        sleep 0.05
    done
    if [ ! -s "$HERE/port.txt" ]; then
        echo "FAIL size=$size: server never published a port"
        kill "$srv" 2>/dev/null || true
        return 1
    fi
    port=$(cat "$HERE/port.txt")
    LIVE_DEST_SIZE=$size "$BIN/freeprobe-plain" "$port" \
        > "$OUT/sweep-$size-client.log" 2>&1
    rc=$?
    wait "$srv" 2>/dev/null || true
    echo "SIZE=$size RC=$rc"
}

for size in 1 1032 2048 4096 8192 16384 200000; do
    run_case "$size"
done

# Frame evidence for the one-byte case: the fault must be in memcpy at pinned
# line 418, not in the caller's delete[]/free().
rm -f "$HERE/port.txt"
python3 "$HERE/fake_s7_server.py" attack "$HERE/port.txt" "$OUT/gdb-server.log" &
srv=$!
for _ in $(seq 1 200); do
    [ -s "$HERE/port.txt" ] && break
    kill -0 "$srv" 2>/dev/null || break
    sleep 0.05
done
port=$(cat "$HERE/port.txt")
LIVE_DEST_SIZE=1 gdb -q -batch -ex "set pagination off" -ex run \
    -ex "bt 4" -ex "info registers rdi rsi" --args "$BIN/freeprobe-plain" "$port" \
    > "$OUT/gdb.log" 2>&1
wait "$srv" 2>/dev/null || true
grep -E "Program received signal|#[0-3] |^rdi|^rsi" "$OUT/gdb.log"
