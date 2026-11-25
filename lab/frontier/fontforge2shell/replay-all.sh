#!/bin/sh
# W17 one-command replay of all three author-side real-build suites.
# Usage from a clean archive:
#   git archive <commit> lab/frontier/fontforge2shell | tar x -C /tmp/ff2s-wit
#   cp lab/frontier/fontforge2shell/src/fontforge-20251009.tar.gz \
#      /tmp/ff2s-wit/lab/frontier/fontforge2shell/src/
#   cd /tmp/ff2s-wit/lab/frontier/fontforge2shell
#   FF2S_TARBALL=src/fontforge-20251009.tar.gz sh replay-all.sh
# Or set FF2S_TARBALL to any local copy of the pinned tarball.
# Offline: no network, no loopback service, no external probe.
set -u
cd "$(dirname "$0")" || exit 1

fail=0
run_suite() {
    suite=$1
    marker=$2
    log="replay-all-$suite.out"
    sh "replay-$suite.sh" > "$log" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ] && grep -qF "$marker" "$log"; then
        printf 'PASS replay-%s.sh rc=0 [%s]\n' "$suite" "$marker"
    else
        printf 'FAIL replay-%s.sh rc=%s want marker [%s]\n' "$suite" "$rc" "$marker"
        fail=$((fail+1))
    fi
}

run_suite real    'REPLAY_REAL_OK: 17/17 stable-lane checks passed'
run_suite nonpie  'REPLAY_NONPIE_OK: 15 checks, 0 failed'
run_suite negdiv  'REPLAY_NEGDIV_OK: 20 checks, 0 failed'

echo '=== normalized evidence hashes ==='
sha256sum \
    truncated.pcf complete.pcf size-91.pcf sponge-32.pcf choice-4-var.pcf \
    value-atk50.pcf value-atkceiling.pcf value-probe.pcf \
    value-nonpie-a.pcf value-nonpie-b.pcf negdiv-atk.pcf \
    replay-negdiv-mapping.out

if [ "$fail" -eq 0 ]; then
    echo 'REPLAY_ALL_OK: 3 suites (17 + 15 + 20 = 52 checks), 0 failed'
else
    echo "REPLAY_ALL_FAIL: $fail suite(s) failed"
fi
exit "$fail"
