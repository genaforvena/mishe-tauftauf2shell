#!/usr/bin/env bash
# One-command independent replay of the lwext4 real-mount (rung 3) and
# adjacent-live-object (rung 4) lanes from a clean git archive.
#
# Usage:
#   bash replay-clean.sh [REF] [DEST]
#     REF  git ref to archive (default HEAD); 352f77e9 pins the recorded run
#     DEST clean destination directory (default: fresh mktemp dir)
#
# The runners assume a provisioned upstream clone, so this helper performs
# that provisioning by public source fetch only (no target host is probed),
# deletes every staged evidence output, then runs run-all.sh, run-real.sh and
# run-victim.sh unmodified. Keep the console it prints as the replay record.
set -euo pipefail

REF="${1:-HEAD}"
DEST="${2:-$(mktemp -d /tmp/lwext4-clean.XXXXXX)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"

VULN_PIN=890484c72dbb321535127625c3686e51f1f424b9
FIX_PIN=b9c842f168e6044bd03fe34e1237eda33c299908

echo "=== lwext4 clean-archive replay: REF=$REF DEST=$DEST ==="
mkdir -p "$DEST"
git -C "$REPO" archive "$REF" lab/frontier/lwext4shell | tar -x -C "$DEST"
cd "$DEST/lab/frontier/lwext4shell"
LAB="$PWD"
UP="$LAB/real/lwext4-upstream"

git clone -q https://github.com/gkostka/lwext4.git "$UP"
git -C "$UP" worktree add -q --detach "$UP/vuln" "$VULN_PIN"
git -C "$UP" worktree add -q --detach "$UP/fixed" "$FIX_PIN"
echo "vuln=$(git -C "$UP/vuln" rev-parse HEAD)"
echo "fixed=$(git -C "$UP/fixed" rev-parse HEAD)"

echo "== remove staged evidence so every check is regenerated =="
rm -rf real/evidence out real/build-*-asan real/build-vuln-plain
rm -f real/driver-vuln real/driver-fixed real/driver-vuln-plain
rm -f real/image-*.ext4
mkdir -p real/evidence out

rc=0
echo "== run-all.sh (verbatim excerpt lane) =="
bash run-all.sh > "$DEST/console-all.log" 2>&1 || rc=$?
grep -E '^(TOTAL:|FAIL )' "$DEST/console-all.log"

echo "== run-real.sh (real ext4_fs_init() mount path) =="
rrc=0
bash run-real.sh > "$DEST/console-real.log" 2>&1 || rrc=$?
grep -E '^(REAL_PASS=|REAL MOUNT REPLAY|FAIL )' "$DEST/console-real.log"
[ "$rrc" -eq 0 ] || rc=$rrc

echo "== run-victim.sh (adjacent live ext4_buf) =="
vrc=0
bash run-victim.sh > "$DEST/console-victim.log" 2>&1 || vrc=$?
grep -E '^(VICTIM_PASS=|ADJACENT OBJECT REPLAY|FAIL )' "$DEST/console-victim.log"
[ "$vrc" -eq 0 ] || rc=$vrc

echo "== fresh raw evidence =="
sha256sum real/evidence/*.out
echo "console logs: $DEST/console-{all,real,victim}.log"
echo "=== REPLAY_RC=$rc ==="
exit "$rc"
