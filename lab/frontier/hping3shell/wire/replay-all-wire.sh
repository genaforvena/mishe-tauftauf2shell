#!/bin/sh
# One-command replay of both hping3shell wire stages (CVE-2026-136131).
# Usage: HPING_SRC=/path/to/pinned/hping-src sh replay-all-wire.sh
# HPING_SRC is only needed when the gitignored ../provision tree is absent,
# e.g. after `git archive HEAD lab/frontier/hping3shell | tar x -C /tmp/...`.
# All traffic stays on 127.0.0.1/127.0.0.2; no pinned source is hand-edited.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p evidence

PINNED_SHA=e8ef2dd63b3f7b5e5d87d14a50bdc64c6befc94a8e21801f060708f2dcbb5e7b
src=${HPING_SRC:-../provision/hping-src}
if [ ! -d "$src" ]; then
    echo "missing pinned hping source tree at $src; set HPING_SRC to its path" >&2
    exit 2
fi
sha=$(sha256sum "$src/display_ipopt.c" | cut -d' ' -f1)
if [ "$sha" != "$PINNED_SHA" ]; then
    echo "pinned display_ipopt.c sha256 $sha, expected $PINNED_SHA" >&2
    exit 2
fi
mkdir -p ../provision
[ -d ../provision/hping-src ] || cp -a "$src" ../provision/hping-src

stage() { # label expected-passes command...
    label=$1; expected=$2; shift 2
    out="evidence/replay-$label.out"
    "$@" >"$out" 2>&1
    rc=$?
    got=$(grep -c '^PASS ' "$out")
    bad=$(grep -c '^FAIL ' "$out")
    if [ "$rc" -eq 0 ] && [ "$got" -eq "$expected" ] && [ "$bad" -eq 0 ]; then
        printf 'STAGE OK %-9s: %s PASS / 0 FAIL rc=0\n' "$label" "$got"
        return 0
    fi
    printf 'STAGE FAIL %-9s: %s PASS / %s FAIL rc=%s (expected %s PASS)\n' \
        "$label" "$got" "$bad" "$rc" "$expected"
    cat "$out"
    return 1
}

failed=0
stage asan 9 sh run-wire.sh || failed=1
stage baseline 3 env NO_INJECT=1 sh plain-proof.sh || failed=1
stage attack 4 sh plain-proof.sh || failed=1
stage fixed 3 sh plain-fixed-proof.sh || failed=1
[ "$failed" -eq 0 ] || exit 1
echo 'REPLAY_ALL_WIRE_OK: 19 checks (9 ASan wire + 4 plain attack + 3 baseline + 3 fixed)'
exit 0
