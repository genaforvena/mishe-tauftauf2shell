#!/bin/sh
# One-command replay of the W8 -O2 fortify-abort result from a clean archive.
# Needs the gitignored pinned source via HPING_SRC. Loopback only, 10 checks.
set -eu
cd "$(dirname "$0")"
PINNED=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b
FIXED=70f0112d12c52d8661736de85e1a5155ba717ca63b09b471cb7aaa7f0ba846c7
src=${HPING_SRC:-../provision/hping-src}
[ "$(sha256sum "$src/display_ipopt.c" | cut -d' ' -f1)" = "$PINNED" ] || {
    echo "HPING_SRC display_ipopt.c is not the pinned bytes"; exit 2; }
mkdir -p compat/net evidence
: > compat/net/bpf.h
rm -rf replay-o2-src replay-o2-fixed-src
cp -a "$src" replay-o2-src
( cd replay-o2-src || exit 1
  ./configure --no-tcl >/dev/null 2>&1
  make -j4 CCOPT='-O2 -g -fcommon -Wall -Wno-unused -I../compat' \
      >../replay-o2-build.log 2>&1 )
cp -a replay-o2-src replay-o2-fixed-src
patch -s -o /tmp/w8-replay-o2-fixed.c replay-o2-fixed-src/display_ipopt.c \
    < ../pinned/fix.patch
cp /tmp/w8-replay-o2-fixed.c replay-o2-fixed-src/display_ipopt.c
[ "$(sha256sum replay-o2-fixed-src/display_ipopt.c | cut -d' ' -f1)" = "$FIXED" ] || {
    echo "fix.patch did not produce the expected fixed source"; exit 2; }
( cd replay-o2-fixed-src || exit 1
  make clean >/dev/null 2>&1
  make -j4 CCOPT='-O2 -g -fcommon -Wall -Wno-unused -I../compat' \
      >../replay-o2-fixed-build.log 2>&1 )

assert() {
    grep -q "^O2 FORTIFY SUMMARY: $1 checks, PASS$" "$2" || {
        echo "REPLAY_O2_FAIL: expected $1 PASS in $2"; cat "$2"; exit 1; }
    echo "STAGE OK $3 $1"
}

NO_INJECT=1 BIN=replay-o2-src/hping3 EXPECT_SHA="$PINNED" \
    RUN_TAG=replay-o2-baseline EXPECT=baseline sh o2-index-proof.sh
assert 4 evidence/o2-replay-o2-baseline-proof.out baseline

BIN=replay-o2-src/hping3 EXPECT_SHA="$PINNED" \
    RUN_TAG=replay-o2 EXPECT=attack sh o2-index-proof.sh
assert 3 evidence/o2-replay-o2-proof.out attack

BIN=replay-o2-fixed-src/hping3 EXPECT_SHA="$FIXED" \
    RUN_TAG=replay-o2-fixed EXPECT=fixed sh o2-index-proof.sh
assert 4 evidence/o2-replay-o2-fixed-proof.out fixed

echo "REPLAY_O2_OK: 11 checks"
