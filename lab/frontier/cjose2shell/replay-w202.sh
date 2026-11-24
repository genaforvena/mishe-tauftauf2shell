#!/bin/sh
# One-command clean-archive replay of the cjose2shell W202 valid-pointer limb.
#
#   git archive HEAD lab/frontier/cjose2shell | tar x -C /tmp/cjose-w202
#   cd /tmp/cjose-w202/lab/frontier/cjose2shell && sh replay-w202.sh
#
# Offline: verifies pins, rebuilds jansson and the pinned cjose trees from
# committed tarballs, runs the direct-call check, rebuilds the loopback
# consumers and drives the W202 valid-pointer token with the W199 fault,
# fixed and safe-input controls. Each case opens one ephemeral 127.0.0.1
# listener; no listener remains. Expected terminal line: REPLAY_W202_OK
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$HERE

(cd "$ROOT" && sha256sum -c PINS.sha256 > /dev/null)

"$ROOT/harness/bootstrap.sh"
grep -qF 'PASS=223 FAIL=0' "$ROOT/harness/evidence/summary.txt"

(cd "$ROOT/w1" && sh build.sh)
sh "$ROOT/w1/validptr-run.sh"

echo REPLAY_W202_OK
