#!/usr/bin/env bash
# Replay the four live loopback cases. Requires the built artifacts in this
# directory (see reports/ffmpeg2shell-live.md for build/fetch commands).
set -u
ROOT=$(cd "$(dirname "$0")" && pwd)
LIB="$ROOT/prefix/lib"
ASAN=${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=0}
mkdir -p "$ROOT/evidence"

run_case() {
    local name=$1 bin=$2 count=$3 len=$4
    local recv="$ROOT/evidence/${name}-recv.log" send="$ROOT/evidence/${name}-send.log"
    (env LD_LIBRARY_PATH="$LIB" ASAN_OPTIONS="$ASAN" timeout 24 "$bin" \
        -hide_banner -loglevel verbose -f data \
        -i 'async:rist://@:5004' -show_packets > "$recv" 2>&1; \
        echo "ffprobe rc=$?" >> "$recv") &
    local rp=$!
    sleep 2
    (env LD_LIBRARY_PATH="$LIB" timeout 20 "$ROOT/rist_sender_live" \
        'rist://127.0.0.1:5004' "$count" "$len" > "$send" 2>&1; \
        echo "sender rc=$?" >> "$send") &
    local sp=$!
    wait $sp $rp
    printf '%-12s ASan_hits=%s  %s\n' "$name" \
        "$(grep -c 'ERROR: AddressSanitizer' "$recv" || true)" \
        "$(grep 'ffprobe rc=' "$recv" | tail -1)"
}

run_case vuln-1  "$ROOT/ffmpeg-n9.0/ffprobe-vuln" 2200 9968
run_case vuln-2  "$ROOT/ffmpeg-n9.0/ffprobe-vuln" 2200 9968
run_case fixed   "$ROOT/ffmpeg-n9.0/ffprobe-fixed" 2200 9968
run_case safe    "$ROOT/ffmpeg-n9.0/ffprobe-vuln" 2200 512
