#!/bin/sh
# One-command author-side replay of the W23 bounded negative. Run from any cwd:
#   sh lab/frontier/libraw2shell/w23/replay.sh
set -u
ORIG=$(pwd)
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE/.." || exit 2
pass=0
fail=0
ok() {
  label=$1
  shift
  if "$@"; then printf 'PASS %s\n' "$label"; pass=$((pass+1))
  else printf 'FAIL %s\n' "$label"; fail=$((fail+1)); fi
}
has() { grep -q "$1" "$2"; }

ok 'hashes of pins, generator, specs, probe and inputs' \
  sh -c 'sha256sum -c w23/hashes.sha256 >w23/replay-hashes.out 2>&1'
ok 'greenzero1 input regenerates byte-exact from spec' \
  sh -c 'python3 craft_uncompressed_poc.py w11/targetbeef.input w23/regen-greenzero1.input w23/greenzero1.json >/dev/null && cmp -s w23/regen-greenzero1.input w23/greenzero1.input'
cd w23 || exit 2
ok 'baseline dead-target reproduces W21 size field' \
  sh -c 'W23_INPUT=../w13/dead-target.input gdb -q -batch -x sizefield.gdb ../o0/LibRaw-0.22.3/bin/dcraw_emu >replay-baseline.txt 2>&1; grep -q "W23 AFTER sf=0xbedbbeef4d03" replay-baseline.txt'
ok 'greenzero1 size field has non-zero high dword' \
  sh -c 'W23_INPUT=../w23/greenzero1.input gdb -q -batch -x sizefield.gdb ../o0/LibRaw-0.22.3/bin/dcraw_emu >replay-greenzero1.txt 2>&1; grep -q "W23 AFTER sf=0x100000000 " replay-greenzero1.txt'
cd "$HERE/.." || exit 2
ok 'plain greenzero1 pad16 rc134 corrupted-size-vs-prev-size' \
  sh -c 'env MALLOC_TOP_PAD_=16777216 plain/LibRaw-0.22.3/bin/dcraw_emu -n 1 w23/greenzero1.input >/dev/null 2>w23/replay-plain.err; [ $? = 134 ] && grep -q "corrupted size vs. prev_size" w23/replay-plain.err'
ok 'fixed greenzero1 pad16 rc0' \
  sh -c 'env MALLOC_TOP_PAD_=16777216 fixed/LibRaw-0.22.3/bin/dcraw_emu -n 1 w23/greenzero1.input >/dev/null 2>w23/replay-fixed.err; [ $? = 0 ] && [ ! -s w23/replay-fixed.err ]'
ok 'no-option greenzero1 pad16 rc0' \
  sh -c 'env MALLOC_TOP_PAD_=16777216 plain/LibRaw-0.22.3/bin/dcraw_emu w23/greenzero1.input >/dev/null 2>w23/replay-none.err; [ $? = 0 ] && [ ! -s w23/replay-none.err ]'

printf 'PASS=%s FAIL=%s\n' "$pass" "$fail"
[ "$fail" = 0 ] && printf 'W23_NEGATIVE_OK\n'
cd "$ORIG" || exit 2
[ "$fail" = 0 ]
