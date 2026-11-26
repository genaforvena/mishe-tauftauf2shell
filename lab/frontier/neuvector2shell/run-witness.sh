#!/usr/bin/env bash
# One-command replay for the neuvector2shell staged evidence.
# Rehashes all four pins, rebuilds every binary and re-asserts the staged
# ASan, fixed-control, safe-control and gdb chosen-byte evidence.
set -u
cd "$(dirname "$0")"

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }

echo "== pin verification =="
for pair in "src/dpi_sig-vulnerable.c 1fbf0ba4aa731f8a92801002d2fe39141c2a88ea9a96d18507af47ae3303072b" \
            "src/dpi_sig-fixed.c cc9d9c48ea07b015c7254946ab1c630f3aea2ce3a80d0042880b5cedaa284b08" \
            "pins/dpi-vulnerable.inc a3f74b69151d28acd5cb80eeb1a79949016598f61e0213272648888bbdcea10f" \
            "pins/dpi-fixed.inc b08af876c7ac71f2f3416b6dc9ee9f0c27816742fc6aea71a4e68bad1431de59"; do
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
