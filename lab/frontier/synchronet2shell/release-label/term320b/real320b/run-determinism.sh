#!/usr/bin/env bash
# W23: determinism sweep of the W21 live shipped-3.20b chosen-pointer replay.
# Runs the unmodified W21 driver three times; each run builds the same pinned
# db9c5d6f tree, starts a fresh loopback-only server on fresh ports, sends the
# 40-byte control and the 64-byte chosen TERM, and preserves the two server
# logs. Nothing here changes the claim: it measures run-to-run stability of
# the chosen bytes and the teardown fault. All clients are 127.0.0.1 only.
set -uo pipefail
HERE=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$HERE" || exit 2
D=$HERE/release-label/term320b/real320b
E=$D/evidence
OUT=$E/determinism
mkdir -p "$OUT" || exit 2

CTRL='REAL_320B_PROBE sizeof=41 l=40 off41=00 cv=00000000 first=(nil) last=(nil)'
PROBE='REAL_320B_PROBE sizeof=41 l=64 off41=42 cv=4853494d first=0x465541544f4f2d45 last=0x5a5a5a5a46554154'
pass=0
fail=0
ck() {
    if [ "$1" = 0 ]; then echo "PASS $2"; pass=$((pass + 1));
    else echo "FAIL $2"; fail=$((fail + 1)); fi
}

for n in 1 2 3; do
    echo "=== RUN $n $(date -u +%FT%TZ) ==="
    bash "$D/run-real320b.sh" > "$OUT/run-$n.log" 2>&1
    rc=$?
    cp "$E/server-control40.log" "$OUT/run-$n-control40.log" 2>/dev/null || true
    cp "$E/server-vuln.log" "$OUT/run-$n-vuln.log" 2>/dev/null || true
    grep -q 'RESULT: PASS=4 FAIL=0' "$OUT/run-$n.log"; ck $? "run-$n driver 4 PASS / 0 FAIL (rc=$rc)"
    grep -qF "$CTRL" "$OUT/run-$n-control40.log"; ck $? "run-$n 40-byte control leaves fields nil/zero"
    grep -qF "$PROBE" "$OUT/run-$n-vuln.log"; ck $? "run-$n chosen pointer pair at +48/+56"
    if grep -q 'destructor begin' "$OUT/run-$n-vuln.log" && ! grep -q 'destructor end' "$OUT/run-$n-vuln.log"; then
        ck 0 "run-$n teardown begins and never completes"
    else
        ck 1 "run-$n teardown begins and never completes"
    fi
done

# The W21 driver restores answer.cpp on its success path; verify that here.
git -C "$HERE/src-tree/320b" diff --quiet -- src/sbbs3/answer.cpp
ck $? "pinned tree answer.cpp restored after all runs"

echo "RESULT: PASS=$pass FAIL=$fail"
test "$fail" -eq 0
