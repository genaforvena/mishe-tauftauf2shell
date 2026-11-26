#!/usr/bin/env bash
# One-command witness replay for the radare2pyc2shell staged evidence.
# Rehashes all pins, rebuilds every binary from scratch and re-asserts ASan,
# fixed-control, safe-control and bounded-sink evidence via run-all.sh.
set -u
cd "$(dirname "$0")"

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }

echo "== pin verification =="
for pair in "src/marshal-6.1.8.c 41698e7886715b57427b166c90101aa132eadec821de66fccbf477a147cbb51c" \
            "src/marshal-fix-6727454.c 3d8b2a625a96a750ad2135a32d975715f91a262d6bd71695b5ed9982bcf0c313" \
            "src/marshal-6.2.0.c 0aedf7fb536fbfeb6c5cdb7804dce6a40e15807cfe107a0ac6c31c7115f4a45c" \
            "src/buf-6.1.8.c 538a6784eeb0e7f673625f73fce58e97c957f2b3dd41b90528d2f4b57493a52f" \
            "pins/get-bytes-vulnerable.inc a3f2083495e1e6205fc77934167ae195a3968607bdc5b24f0aa653f6962c396f" \
            "pins/get-bytes-fixed.inc 8e41575a6e315364b95e125524db2fa9e28d8347b27dae8bf5c4004c95cff9ba" \
            "pins/ascii-readers.inc d19406980365f39859bcee067be6a940fcad812ddf23d0db48476484b16ed26e" \
            "pins/buf-sink.inc 4f3e1082ed37fd99f92d010c3b7037ef955583c9b795603d4c1de89892d5c9dd" \
            "harness/driver.c 6995deba366eba8e92523316bf3230470397cce4291538b4912d5290ad485ce3"; do
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
