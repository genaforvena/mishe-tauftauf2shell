#!/usr/bin/env bash
# W3 mask/slack replay for CVE-2026-116791. Loopback only; pinned .inc untouched.
# Runs the plain vulnerable pin with an attacker-chosen 4-byte mask override.
set -u
cd "$(dirname "$0")" || exit 2
HERE=$PWD
FNS_DIR=$HERE/../../frontier/sofiasip2shell/harness
EVID=$HERE/evidence/w3
mkdir -p "$EVID"

# Re-assert the frontier-verified verbatim pinned function hash (W3 does not
# touch the pinned slice or the canonical run.sh evidence).
want=b96477e02ac1975ed7b3305a0110271dd0f91484334c0cd6f5ec4372b674ee80
got=$(sha256sum "$FNS_DIR/fns-1.13.17.inc" | cut -d' ' -f1)
if [ "$got" != "$want" ]; then
  echo "FATAL: fns-1.13.17.inc hash mismatch ($got)" >&2
  exit 2
fi

CC=${CC:-gcc}
$CC -O0 -g -fno-omit-frame-pointer -Wall -DPLAIN_MODE \
  -DPIN='"v1.13.17"' -DFNS='"fns-1.13.17.inc"' -I"$FNS_DIR" \
  real_layout.c -o plain-mask || exit 2

run() { # tag mask mode [bbuflen]
  local tag=$1 mask=$2
  shift 2
  SIA_MASK=$mask ./plain-mask "$@" >"$EVID/$tag.out" 2>"$EVID/$tag.err"
  echo $? >"$EVID/$tag.rc"
  echo "=== $tag (rc=$(cat "$EVID/$tag.rc")) mask=$mask $* ==="
  grep -E 'PRECALL|META_OFF|PREV_INUSE|GEOM_VICTIM|CONTROL=|XOR_DELTA|corrupted' \
    "$EVID/$tag.err" | head -20
}

run odd-default        415a4243 abort
run even-default       405a4243 abort
run zero-default       00000000 abort
run small-delta-default 00000100 abort
run odd-geom           415a4243 geom 65527
run even-geom          405a4243 geom 65527
run zero-geom          00000000 geom 65527
run small-delta-geom   00000100 geom 65527
run odd-realloc        415a4243 realloc
run even-realloc       405a4243 realloc
for n in 65528 65529 65530 65531 65536; do run slack-$n 415a4243 geom $n; done
