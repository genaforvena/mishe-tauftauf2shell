#!/bin/sh
# One-command clean-archive replay of every libraw2shell frontier claim.
# Run from any cwd after extracting a git archive of this tree:
#
#   git archive HEAD lab/frontier/libraw2shell | tar x -C /tmp/lr-frontier
#   cd /tmp/lr-frontier/lab/frontier/libraw2shell && sh replay-frontier.sh
#
# Existing per-claim scripts are called unmodified. Their hash manifests pin
# committed source, specs and inputs; -g build products are verified by the
# gdb/plain/ASan behavior checks, not by binary hashes, after a clean build.
set -u
cd "$(dirname "$0")" || exit 2
WORK=${1:-/tmp/libraw2shell-frontier-replay}
mkdir -p "$WORK"

fail=0
run() { # label cmd...
    label=$1; shift
    "$@" >"$WORK/$label.log" 2>&1
    rc=$?
    if [ "$rc" = 0 ]; then
        printf 'PASS %s\n' "$label"
    else
        printf 'FAIL %s rc=%s\n' "$label" "$rc"
        fail=1
    fi
}

run bootstrap        sh bootstrap.sh
run w13-w14-w15      sh replay-all.sh "$WORK/all"
run wire             sh wire/run.sh w15/band150.input "$WORK/wire-out"
run w21              sh w21/replay.sh
run w23              sh w23/replay.sh
run w29              sh w29/replay.sh

printf 'RECEIPTS\n'
grep -h -E '^(REPLAY_W13_W14_W15_OK|WIRE_OOB_OK|W21_OK|W23_NEGATIVE_OK|W29_OK)$' \
    "$WORK/w13-w14-w15.log" "$WORK/wire.log" "$WORK/w21.log" "$WORK/w23.log" "$WORK/w29.log"

if [ "$fail" = 0 ]; then
    echo REPLAY_FRONTIER_OK
    exit 0
fi
echo REPLAY_FRONTIER_FAIL
exit 1
