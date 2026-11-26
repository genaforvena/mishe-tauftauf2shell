#!/usr/bin/env bash
# One-command witness replay for the lwext4shell staged evidence.
# Rehashes all five pins and the driver, rebuilds every binary and re-asserts
# ASan, fixed-control, safe-control and plain chosen-bit readback evidence.
set -u
cd "$(dirname "$0")"

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }

echo "== pin verification =="
for pair in "src/ext4_fs-vulnerable.c c14c4c3378abb985c28025f35d142c753e05bb6df5d171282ed83d7ccf6c09eb" \
            "src/ext4_fs-fixed.c b259a4bbe8a836d0ce7b78e6dbf0fb9eb29dbe056ce93b69cab7a2975de7bd1f" \
            "pins/lwext4-vulnerable.inc c93eaa348724a76546e9d9af248d816569f948bf7823590fdab95f38e8df9e07" \
            "pins/lwext4-fixed.inc 516bdf3b178b121881fec04d9c4f9f63a8a6a1ed53fe83155357fa9ea8d644a5" \
            "harness/driver.c 02d76df4f1ef5fdd231725e8d373f9f20a8bbf88feef144ebcac80c1a7549b42"; do
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
grep -E '^(PASS|FAIL) ' out-replay.log | tail -20 || true

echo "REPLAY_PASS=$pass REPLAY_FAIL=$fail"
if [ "$fail" -eq 0 ]; then
    echo "WITNESS REPLAY PASS"
    exit 0
fi
echo "WITNESS REPLAY FAIL"
exit 1
