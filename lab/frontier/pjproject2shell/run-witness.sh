#!/usr/bin/env bash
# One-command replay for the pjproject2shell staged evidence.
# Rehashes all four pins, rebuilds every binary and re-asserts the staged
# ASan, fixed-control, safe-control and chosen-byte evidence.
set -u
cd "$(dirname "$0")"

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }

echo "== pin verification =="
for pair in "src/avi_player-vuln.c 1ccafcd255ad996e572753495191ff5347b2062c9152617458425f30c9446081" \
            "src/avi_player-fixed.c dae6aeee810d88173657cefb3486f89bdee77dbe87b2520a5ae784f854fc5042" \
            "pins/avi-vulnerable.inc 45fe04f09520dfef6f2cc52f70d6293a4fdd96e7f76d6eb41a79e2586e710ba1" \
            "pins/avi-fixed.inc 2cc1805d5dee8959837926dcb492ffb3b53de4b2a2b4e063f0afc4f3f11139de"; do
    set -- $pair
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] && ok "pin $1" || bad "pin $1"
done

echo "== clean rebuild and full run =="
rm -rf out
if bash run-all.sh > out-replay.log 2>&1; then
    ok "run-all.sh full replay"
else
    bad "run-all.sh full replay"
fi
grep -E '^TOTAL:' out-replay.log || true
grep -E '^(PASS|FAIL) ' out-replay.log | tail -30 || true

echo "REPLAY_PASS=$pass REPLAY_FAIL=$fail"
if [ "$fail" -eq 0 ]; then
    echo "WITNESS REPLAY PASS"
    exit 0
fi
echo "WITNESS REPLAY FAIL"
exit 1
