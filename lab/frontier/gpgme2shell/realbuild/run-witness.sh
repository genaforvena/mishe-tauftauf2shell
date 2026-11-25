#!/bin/sh
# One-command clean-archive replay of the W11 EOF suite (commit 057e2e2a).
# Usage: sh run-witness.sh [OUTDIR]
#
# Run from the plant git checkout. The four provisioned GPGME tarballs are
# copied from this checkout's realbuild/src (already sha256-verified by
# build-real.sh), so the replay makes no network requests and touches no
# lab instance. Everything else comes from the clean archive of 057e2e2a.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel)
COMMIT=057e2e2a
OUT=${1:-$(mktemp -d /tmp/gpgme-w11-witness.XXXXXX)}
mkdir -p "$OUT"
git -C "$REPO" archive "$COMMIT" lab/frontier/gpgme2shell | tar -x -C "$OUT"
SRC=$OUT/lab/frontier/gpgme2shell/realbuild/src
mkdir -p "$SRC"
cp "$HERE"/src/*.tar.bz2 "$SRC"/
D=$OUT/lab/frontier/gpgme2shell/realbuild
echo "WITNESS OUT=$OUT COMMIT=$COMMIT"
(cd "$D" && sh build-real.sh)
(cd "$D" && sh run-eof.sh)
echo "REPLAY OK OUT=$OUT"
