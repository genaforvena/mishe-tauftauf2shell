#!/usr/bin/env bash
# Allocator-layout probe on the plain (non-ASan) n9.0 receive path.
# Forces glibc to serve the 8 MiB async FIFO from brk with
# MALLOC_MMAP_THRESHOLD_, then replays the W2 loopback stream.
set -u
ROOT=$(cd "$(dirname "$0")" && pwd)
LIB="$ROOT/prefix/lib"
mkdir -p "$ROOT/evidence"

run_case() {
    local name=$1 bin=$2 count=$3 len=$4
    local recv="$ROOT/evidence/${name}-recv.log" send="$ROOT/evidence/${name}-send.log"
    (env LD_LIBRARY_PATH="$LIB" MALLOC_MMAP_THRESHOLD_=16777216 \
        timeout 24 "$bin" -hide_banner -loglevel verbose -f data \
        -i 'async:rist://@:5004' -show_packets > "$recv" 2>&1; \
        echo "ffprobe rc=$?" >> "$recv") &
    local rp=$!
    sleep 2
    (env LD_LIBRARY_PATH="$LIB" timeout 20 "$ROOT/rist_sender_live" \
        'rist://127.0.0.1:5004' "$count" "$len" > "$send" 2>&1; \
        echo "sender rc=$?" >> "$send") &
    local sp=$!
    wait $sp $rp
    printf '%-20s %s | %s\n' "$name" \
        "$(grep 'ffprobe rc=' "$recv" | tail -1)" \
        "$(grep -E 'SIGSEGV|signal|Segmentation' "$recv" | head -1)"
}

run_case layout-brk-vuln     "$ROOT/plain/src/ffprobe" 2200 9968
run_case layout-brk-fixed    "$ROOT/ffmpeg-n9.0/ffprobe-fixed" 2200 9968
run_case layout-brk-safe     "$ROOT/plain/src/ffprobe" 2200 512
