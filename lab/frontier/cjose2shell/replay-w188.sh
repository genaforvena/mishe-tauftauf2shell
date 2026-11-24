#!/bin/sh
# One-command clean-archive replay of the cjose2shell W188 rung-4 limb.
#
# From a fresh archive of committed source only, e.g.:
#   git archive HEAD lab/frontier/cjose2shell | tar x -C /tmp/cjose-replay
#   cd /tmp/cjose-replay/lab/frontier/cjose2shell && sh replay-w188.sh
#
# Offline. Rebuilds jansson and all pinned cjose trees from the committed
# tarballs, verifies PINS.sha256, runs the 48-invocation direct-call check,
# then runs the fptr scenario with vulnerable/fixed and attack/safe controls.
# No listener, Apache, private key, network or shell command from the harness.
# Expected terminal line: REPLAY_W188_OK
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$HERE

(cd "$ROOT" && sha256sum -c PINS.sha256 > /dev/null)

"$ROOT/harness/bootstrap.sh"
grep -qF 'PASS=223 FAIL=0' "$ROOT/harness/evidence/summary.txt"

"$ROOT/fptr/run.sh"

V="$ROOT/fptr/evidence/vulnerable-fptr.out"
VS="$ROOT/fptr/evidence/vulnerable-fptrsafe.out"
F="$ROOT/fptr/evidence/fixed-fptr.out"
FS="$ROOT/fptr/evidence/fixed-fptrsafe.out"

grep -qF 'GROOM_OK=1' "$V"
grep -qF 'CEK_LEN_AFTER=768' "$V"
grep -qF 'BENIGN_MARKER_EXECUTED' "$V"
grep -qF 'MARKER_CALLED=1' "$V"

for f in "$VS" "$F" "$FS"; do
    grep -qF 'MARKER_CALLED=0' "$f"
    ! grep -qF 'BENIGN_MARKER_EXECUTED' "$f"
done

echo REPLAY_W188_OK
