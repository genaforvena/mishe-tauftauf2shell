#!/bin/bash
# One-command replay of the W9/W10 wd_nodes direct-call harness A-G at the
# published scope: chosen-value writes in the adjacent POOL_CONFIG slot on
# the pinned 4.7.2 parser object, N=128 and 4.7.3 fixed controls, ASan clean.
# No daemon, no loopback sockets, no ports. No new claim, no rung change.
#
# Run from a clean git archive containing lab/frontier/pgpool2shell and
# lab/pgpool2shell. PGPOOL_LAB must point at the provisioned lab holding the
# two pinned (gitignored) tarballs:
#
#   PGPOOL_LAB=/abs/path/to/lab/frontier/pgpool2shell \
#     bash lab/pgpool2shell/wdnodes/run-harness-witness.sh
#
# A fresh TMPDIR forces clean 4.7.2/4.7.3 plain and ASan builds from the
# verified tarballs and leaves the caller's TMPDIR untouched.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
LAB="${PGPOOL_LAB:-}"

if [ -z "$LAB" ] || [ ! -f "$LAB/src/pgpool-II-4.7.2.tar.gz" ] ||
   [ ! -f "$LAB/src/pgpool-II-4.7.3.tar.gz" ]; then
    echo "set PGPOOL_LAB to the provisioned lab/frontier/pgpool2shell with both pinned tarballs" >&2
    exit 2
fi

SRC="$ROOT/lab/frontier/pgpool2shell/src"
mkdir -p "$SRC"
for ver in 4.7.2 4.7.3; do
    tarball="$SRC/pgpool-II-$ver.tar.gz"
    if [ ! -e "$tarball" ] || [ -L "$tarball" ]; then
        ln -sfn "$LAB/src/pgpool-II-$ver.tar.gz" "$tarball"
    fi
done
(cd "$SRC" && sha256sum -c SHA256SUMS) || exit 2

BUILD="$(mktemp -d /tmp/pgpool-w9-harness-witness.XXXXXX)" || exit 2
export TMPDIR="$BUILD"
mkdir -p "$TMPDIR"
cp "$HERE/EVIDENCE_HASHES.txt" "$BUILD/expected-hashes.txt"

echo "=== building pinned 4.7.2/4.7.3 plain and ASan objects in fresh TMPDIR ==="
bash "$HERE/run-harness.sh" >"$BUILD/harness.log" 2>&1 || {
    echo "harness failed; tail of $BUILD/harness.log:" >&2
    tail -40 "$BUILD/harness.log" >&2
    exit 2
}
grep -E '^(=== A:|=== B:|=== C:|=== D:|=== E:|=== F:|=== G:|###|rc=|==[0-9]+==ERROR|SUMMARY:)' \
    "$BUILD/harness.log" || true

if diff -u "$BUILD/expected-hashes.txt" "$HERE/EVIDENCE_HASHES.txt"; then
    echo "HARNESS REPLAY PASS: 7 normalized hashes match; build log $BUILD/harness.log"
else
    echo "HARNESS REPLAY FAIL: hash diff above; build log $BUILD/harness.log" >&2
    exit 1
fi
