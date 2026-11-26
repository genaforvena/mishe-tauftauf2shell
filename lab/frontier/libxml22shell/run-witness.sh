#!/usr/bin/env bash
# One-command replay for the libxml22shell staged evidence.
# Verifies all four pinned artifacts, rebuilds every binary from source and
# asserts the staged ASan, fixed-control, negative and chosen-byte evidence.
set -u
cd "$(dirname "$0")"

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }

echo "== pin verification =="
for pair in "pins/dict-v2.15.3.c 416253664eb3d95a393be6c61c649a1b5600729bbd1e3ce9123df08b12d8f388" \
            "pins/dict-v2.15.4.c 2663392f29dd45eb7ad802c471e146d4f6f509e317a4938b496920b4ea0228b4" \
            "pins/dict-vulnerable.inc c2a4a0ed9ffe8fabffc9f0e19de8c3d1ca59fee80dc68f454211ad511a7f0d9a" \
            "pins/dict-fixed.inc 035611cca31f6bdb67b030c221c8fb7445750d841479e6f4f2a7e8874c28b9d4"; do
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
