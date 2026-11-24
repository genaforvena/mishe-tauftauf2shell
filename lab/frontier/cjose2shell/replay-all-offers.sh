#!/bin/sh
# One-command clean-archive replay of all three offered cjose2shell rung-4 limbs.
#
#   git archive HEAD lab/frontier/cjose2shell | tar x -C /tmp/cjose-offers
#   cd /tmp/cjose-offers/lab/frontier/cjose2shell && sh replay-all-offers.sh
#
# Offline, loopback-only. Runs, in order:
#   W199 (#3832): wire-chosen pointer reaches strcmp in the real decrypt path
#   W202 (#3855): valid build-known string address carried on the wire
#   W203 (#3861/#3862): wire-chosen fns pointer -> benign marker via jwk_release
# Each limb re-verifies the pins and the exact PASS=223 FAIL=0 direct-call
# trace, and each server opens one ephemeral 127.0.0.1 port per process that
# is closed before the script continues. No listener remains.
# Expected final line: REPLAY_ALL_OFFERS_OK
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

sh "$HERE/replay-w199.sh"
sh "$HERE/replay-w202.sh"
sh "$HERE/replay-w203.sh"

echo REPLAY_ALL_OFFERS_OK
