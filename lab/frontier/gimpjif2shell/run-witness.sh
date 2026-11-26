#!/usr/bin/env bash
# One-command witness replay for the gimpjif2shell staged evidence.
# Rehashes all four pins and the driver, rebuilds every binary and re-asserts
# ASan, fixed-control, safe-control, plain chosen-byte and negative evidence.
set -u
cd "$(dirname "$0")"

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }

echo "== pin verification =="
for pair in "src/file-gif-load-vulnerable.c 7811585724082652312f95018cd0629bddce0557326173b9242d2457ce66273d" \
            "src/file-gif-load-fixed.c 703c1e124d3bf8e1dc5f92a0cf615f29f54d1fed401984881eb6d0b9c9a478c6" \
            "pins/jif-vulnerable.inc 36288ad05b7a57b9f12c95e0d8f780ef84838581c4f6ebd3b01b0fe42c4fc032" \
            "pins/jif-fixed.inc 98d710f4bf9002adaa3941159f8d9705e6a6ed6b92be190f7509a801393d2f50" \
            "harness/driver.c d31aed1d1eaa5d3db82d06eae708b9be944457e8094a43c37e22d97655044a92"; do
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
