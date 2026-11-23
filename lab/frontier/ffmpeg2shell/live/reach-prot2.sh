#!/usr/bin/env bash
# W4: after the W3 prot overwrite, force prot to a valid neighbouring protocol
# table under gdb and observe whether a NATURAL dispatch goes through it.
# Debugger-forced pointer write: reachability measurement only, not wire control.
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
local_gdb=$!
sleep 3
(env LD_LIBRARY_PATH="$LIB" timeout 30 "$ROOT/rist_sender_live" \
    'rist://127.0.0.1:5004' 2200 9968 > "$SEND" 2>&1; \
    echo "sender rc=$?" >> "$SEND") &
local_sender=$!
wait $local_sender $local_gdb
printf 'RP result: %s | %s\n' \
    "$(grep -c 'RP WATCH HIT' "$OUT") watch hits" \
    "$(grep -E 'RP SET prot|Breakpoint 2, file_read|RP NEXT STOP' "$OUT" | tr '\n' ' ')"
