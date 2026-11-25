#!/bin/sh
# One-command replay of the W6 chosen-RNG-output proof from a clean archive.
# Run from anywhere; needs the gitignored pinned source tree via HPING_SRC.
# All traffic stays on 127.0.0.x on lo; no pinned source is hand-edited.
set -eu
cd "$(dirname "$0")"
PINNED=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b
FIXED=70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7
src=${HPING_SRC:-../provision/hping-src}
[ -f "$src/display_ipopt.c" ] || { echo "HPING_SRC missing: $src"; exit 2; }
[ "$(sha256sum "$src/display_ipopt.c" | cut -d' ' -f1)" = "$PINNED" ] || {
    echo "HPING_SRC display_ipopt.c is not the pinned bytes"; exit 2; }

mkdir -p compat/net evidence
: > compat/net/bpf.h
rm -rf replay-src replay-fixed-src
cp -a "$src" replay-src
( cd replay-src || exit 1
  [ -f Makefile ] || ./configure --no-tcl >/dev/null 2>&1
  make -j4 CCOPT='-O0 -g -fcommon -Wall -Wno-unused -I../compat' \
      >../replay-rngctl-build.log 2>&1 )
cp -a replay-src replay-fixed-src
patch -s -o /tmp/w6-replay-fixed.c replay-fixed-src/display_ipopt.c < ../pinned/fix.patch
cp /tmp/w6-replay-fixed.c replay-fixed-src/display_ipopt.c
[ "$(sha256sum replay-fixed-src/display_ipopt.c | cut -d' ' -f1)" = "$FIXED" ] || {
    echo "fix.patch did not produce the expected fixed source"; exit 2; }
( cd replay-fixed-src || exit 1
  make clean >/dev/null 2>&1
  make -j4 CCOPT='-O0 -g -fcommon -Wall -Wno-unused -I../compat' \
      >../replay-rngctl-fixed-build.log 2>&1 )

assert() {
    grep -q "^RNGCTL SUMMARY: $1 checks run, PASS$" "$2" || {
        echo "REPLAY_RNGCTL_FAIL: expected $1 PASS in $2"; cat "$2"; exit 1; }
    echo "STAGE OK $3 $1"
}

NO_INJECT=1 FILL=32 BIN=replay-src/hping3 EXPECT_SHA="$PINNED" \
    RUN_TAG=replay-baseline EXPECT=baseline sh rngctl-proof.sh
assert 4 evidence/rngctl-replay-baseline-proof.out baseline

FILL=32 BIN=replay-src/hping3 EXPECT_SHA="$PINNED" \
    RUN_TAG=replay EXPECT=attack sh rngctl-proof.sh
assert 6 evidence/rngctl-replay-32-proof.out fill32

FILL=64 BIN=replay-src/hping3 EXPECT_SHA="$PINNED" \
    RUN_TAG=replay EXPECT=attack sh rngctl-proof.sh
assert 6 evidence/rngctl-replay-64-proof.out fill64

FILL=32 BIN=replay-fixed-src/hping3 EXPECT_SHA="$FIXED" \
    RUN_TAG=replay-fixed EXPECT=baseline sh rngctl-proof.sh
assert 4 evidence/rngctl-replay-fixed-32-proof.out fixed

echo "REPLAY_RNGCTL_OK: 20 checks"
