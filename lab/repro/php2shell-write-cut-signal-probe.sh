#!/bin/bash
# Wake 72 replay contract: no-clamp, no-preload write-interruption negative.
# Builds and runs the standalone pwrite/signal probe on the three signals
# FPM could plausibly deliver without killing a worker. A short pwrite with
# a surviving process is the positive condition for a splice without
# RLIMIT_FSIZE; all-full writes are the preserved negative.
set -u
HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
BIN=${1:-/tmp/php2shell-write-cut-signal-probe}
cc -O2 -o "$BIN" "$HERE/php2shell-write-cut-signal-probe.c" || exit 2
SHORT=0
for s in SIGUSR1 SIGCONT SIGWINCH; do
    out=$(timeout 60 "$BIN" "$s")
    printf '%s\n' "$out"
    line=$(printf '%s\n' "$out" | sed -n 's/^\(signal=[^ ]*\) pwrite=\([0-9-]*\) of \([0-9]*\).*/\1 \2 \3/p')
    set -- $line
    [ $# -eq 3 ] || { echo "verdict=PROBE_ERROR ($s)"; exit 2; }
    [ "$2" = "$3" ] || SHORT=1
done
if [ "$SHORT" = 1 ]; then
    echo "verdict=SHORT_WRITE_POSSIBLE — investigate FPM path"
else
    echo "verdict=NO_SHORT_WRITE — handled signals do not interrupt pwrite"
fi
