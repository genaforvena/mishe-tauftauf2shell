#!/usr/bin/env bash
# One-command replay for the rpm2shell staged evidence.
# Verifies all four pinned artifacts, rebuilds every binary from source and
# asserts the staged ASan, fixed-control, safe-control and chosen-byte evidence.
set -u
cd "$(dirname "$0")"

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }

echo "== pin verification =="
for pair in "pins/rpmfi-vulnerable.cc 51d5d7c96773ca2e00c20e5cba7f049d896300d9f255d0fffadd4193fa7ccf27" \
            "pins/rpmfi-fixed.cc eaca65fdb04b9b8fe7647f2df4aa033d7b40d850500e7c82f9a91a3d87cb376a" \
            "pins/iter-vulnerable.inc dd72be1bdb92c68b2d97e38f977344cc5b411c56ee16952e2d1010d8ed49e9ff" \
            "pins/iter-fixed.inc 0c00ded194575ec9649e3532ff09713faa5e96b36acb10524fb5adc776b92721"; do
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
