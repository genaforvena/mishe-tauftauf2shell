#!/usr/bin/env bash
# W4: benign marker side effect from wire-chosen interrupt callback.
set -u
ROOT=$(cd "$(dirname "$0")" && pwd)
LIB="$ROOT/prefix/lib"
name=${1:-mc-puts}; bin=${2:-$ROOT/plain/src/ffprobe_g}
prot=${3:-0x55555584f5a0}; ring=${4:-0x5555558d1fe0}
priv=${5:-0x5555560d2100}; cb=${6:-0x7ffff7a87cc0}
opaque=${7:-0x5555560d20d0}; len=${8:-9968}
mkdir -p "$ROOT/evidence"
OUT="$ROOT/evidence/${name}.log"; SEND="$ROOT/evidence/${name}-send.log"
(env LD_LIBRARY_PATH="$LIB" MALLOC_MMAP_THRESHOLD_=16777216 \
    timeout 50 gdb -q -batch -x "$ROOT/marker-control.cmd" \
    --args "$bin" -hide_banner -loglevel verbose -f data \
    -i async:rist://@:5004 -show_packets > "$OUT" 2>&1; \
    echo "gdb rc=$?" >> "$OUT") &
gdb_pid=$!
sleep 3
(env LD_LIBRARY_PATH="$LIB" timeout 35 "$ROOT/rist_sender_marker" \
    'rist://127.0.0.1:5004' 2200 "$len" "$prot" "$ring" "$priv" "$cb" "$opaque" \
    > "$SEND" 2>&1; echo "sender rc=$?" >> "$SEND") &
sender_pid=$!
wait $sender_pid $gdb_pid
printf '%-12s hits=%s marker=%s puts_bp=%s\n' "$name" \
    "$(grep -c 'MC FIRST HIT' "$OUT")" \
    "$(grep -c 'FFMPEG2SHELL_WIRE_MARKER' "$OUT")" \
    "$(grep -c 'Breakpoint 3, puts' "$OUT")"
