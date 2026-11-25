#!/bin/sh
# drwav2shell one-command replay from a clean archive of this directory.
#
#   git archive HEAD lab/frontier/drwav2shell | tar x -C /tmp/drwav-replay
#   cd /tmp/drwav-replay/lab/frontier/drwav2shell
#   sh replay-frontier.sh
#
# Runs the staged harness plus all four real-consumer lanes. Each lane writes
# its own raw evidence under its evidence/ directory; this script only adds
# summary files under evidence/replay/. It exits 0 only when every lane's own
# PASS/FAIL summary has zero failures and the expected total is present.
set -u
HERE=$(cd "$(dirname "$0")" && pwd -P) || exit 1
cd "$HERE" || exit 1
mkdir -p evidence/replay
SUMMARY=evidence/replay/summary.txt
: >"$SUMMARY"
overall=0

lane() {
    name=$1
    shift
    out="evidence/replay/$name.out"
    if "$@" >"$out" 2>&1; then rc=0; else rc=$?; fi
    total=$(grep -m1 'TOTAL PASS=' "$out" 2>/dev/null || true)
    if [ "$rc" -eq 0 ] && [ -n "$total" ] && case "$total" in *"FAIL=0"*) true;; *) false;; esac; then
        printf 'OK   %-10s rc=%s %s\n' "$name" "$rc" "$total" | tee -a "$SUMMARY"
    else
        printf 'FAIL %-10s rc=%s %s (see %s)\n' "$name" "$rc" "${total:-no TOTAL line}" "$out" | tee -a "$SUMMARY"
        overall=1
    fi
}

lane harness sh harness/run-all.sh
lane consumer sh consumer/run-consumer.sh
lane appdest sh consumer/run-appdest.sh
lane nopie sh consumer/run-nopie.sh
lane marker sh consumer/run-marker.sh

printf 'REPLAY_FRONTIER_%s\n' "$([ "$overall" -eq 0 ] && echo OK || echo FAIL)" | tee -a "$SUMMARY"
exit "$overall"
