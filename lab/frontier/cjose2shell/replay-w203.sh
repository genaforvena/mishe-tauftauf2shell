#!/bin/sh
# One-command clean-archive replay of the cjose2shell W203 wire-marker limb.
#
#   git archive HEAD lab/frontier/cjose2shell | tar x -C /tmp/cjose-w203
#   cd /tmp/cjose-w203/lab/frontier/cjose2shell && sh replay-w203.sh
#
# Offline: pins, jansson and pinned cjose rebuild from committed tarballs,
# direct-call check, then the loopback HTTP marker limb with its fixed and
# safe-input controls. One ephemeral 127.0.0.1 listener per process.
# Expected terminal line: REPLAY_W203_OK
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$HERE

(cd "$ROOT" && sha256sum -c PINS.sha256 > /dev/null)

"$ROOT/harness/bootstrap.sh"
grep -qF 'PASS=223 FAIL=0' "$ROOT/harness/evidence/summary.txt"

sh "$ROOT/w1/wmarker/run.sh"

echo REPLAY_W203_OK
