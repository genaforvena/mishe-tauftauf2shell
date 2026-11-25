#!/bin/sh
# Consolidated one-command replay of every n2n2shell lane on 127.0.0.1:
#   harness          - stand-in pinned decoder (15 checks)
#   replay-live      - live supernode: ASan stack write, chosen bytes,
#                      gdb slots and peer-forward re-emission (22 checks)
#   W10              - wire-chosen comm pointer from a gdb calibration value
#                      (9 checks)
#   W11              - wire-only fixed-address comm pointer, live after wire
#                      (13 checks)
#   W13              - dead spill-slot read negative plus live watch control
#                      (11 checks)
#   W15              - third-build indirect-branch sweep (7 checks)
# No external network contact; each supernode binds loopback only.
#
# From a clean git archive of this tree:
#   git archive HEAD lab/frontier/n2n2shell | tar x -C /tmp/n2n-archive
#   sh /tmp/n2n-archive/lab/frontier/n2n2shell/live/replay-all.sh
#
# Prints "REPLAY_ALL_RESULT <n> PASS / <m> FAIL" and "REPLAY_ALL_OK" only when
# every lane returns 0. Per-lane stdout/stderr is kept at $LOGDIR (TMPDIR or
# /tmp, set REPLAY_LOGDIR to choose); it is never in the repo.
set -u
HERE=$(cd "$(dirname "$0")" || exit 1; pwd)
N2N=$(cd "$HERE/.." || exit 1; pwd)
LOGDIR=${REPLAY_LOGDIR:-${TMPDIR:-/tmp}/n2n2shell-replay-all.$$}
PASS=0
FAIL=0
mkdir -p "$LOGDIR" || exit 1

run_lane() {
    label=$1
    script=$2
    shift 2
    printf '== %s ==\n' "$label"
    # shellcheck disable=SC2086
    PORT_BASE="$1" sh "$script" >"$LOGDIR/$label.log" 2>&1
    rc=$?
    sed -n -e 's/^/  /' "$LOGDIR/$label.log"
    if [ "$rc" -eq 0 ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf 'LANE FAILED: %s (rc %s), see %s\n' "$label" "$rc" "$LOGDIR/$label.log"
    fi
}

# Pins are checked inside replay-live; fail early here too so an archive
# mismatch cannot be mistaken for a lane failure.
if (cd "$N2N" && sha256sum -c pins.sha256) >"$LOGDIR/pins.log" 2>&1; then
    PASS=$((PASS + 1))
    printf '== pins ==\n  %s OK\n' "$(grep -c ': OK' "$LOGDIR/pins.log")"
else
    FAIL=$((FAIL + 1))
    printf 'PINS FAILED, see %s\n' "$LOGDIR/pins.log"
fi

run_lane harness "$N2N/harness/run.sh" 18500
run_lane live "$HERE/replay-live.sh" 18700
run_lane w10 "$HERE/w10_pointer_control.sh" 18950
run_lane w11 "$HERE/w11_fixed_pointer.sh" 19120
run_lane w13 "$HERE/w13_spill_read.sh" 19300
run_lane w15 "$HERE/w15_indirect_sweep.sh" 19500

printf 'REPLAY_ALL_RESULT %s PASS / %s FAIL\n' "$PASS" "$FAIL"
printf 'REPLAY_ALL_LOGDIR %s\n' "$LOGDIR"
if [ "$FAIL" -eq 0 ]; then
    printf 'REPLAY_ALL_OK\n'
    exit 0
fi
exit 1
