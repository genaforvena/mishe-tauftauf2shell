#!/bin/bash
# One-command replay of the pgpool2shell W9/W10/W11 wd_nodes branch at the
# published scope: W10 wire-reachable chosen-value bytes on a live 4.7.2
# watchdog child, W11 authkey-set condition, and the two live-gdb readbacks.
# No new claim, no rung change, no command execution.
#
# Run from a clean git archive containing lab/frontier/pgpool2shell and
# lab/pgpool2shell. PGPOOL_LAB must point at the provisioned lab holding the
# two pinned (gitignored) tarballs:
#
#   PGPOOL_LAB=/abs/path/to/lab/frontier/pgpool2shell \
#     bash lab/pgpool2shell/wdnodes/wire/run-witness.sh
#
# Loopback ports 19003-19006 are used; every script refuses to start if they
# are busy and kills only the processes it started. Fresh TMPDIR gives clean
# builds and leaves the caller's TMPDIR untouched.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../../" && pwd)"
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

BUILD="$(mktemp -d /tmp/pgpool-w9-witness.XXXXXX)" || exit 2
export TMPDIR="$BUILD"
mkdir -p "$TMPDIR"
cp "$HERE/EVIDENCE_HASHES.txt" "$BUILD/expected-hashes.txt"

echo "=== building plain pinned 4.7.2 and 4.7.3 from the verified tarballs ==="
bash "$ROOT/lab/frontier/pgpool2shell/harness/run.sh" >"$BUILD/build.log" 2>&1 || {
    echo "build failed; tail of $BUILD/build.log:" >&2
    tail -40 "$BUILD/build.log" >&2
    exit 2
}

cd "$HERE" || exit 2
echo "=== W10: three loopback wire cases (~67 s) ==="
bash run.sh || exit 1
echo "=== W10: live-gdb readbacks (~30 s each) ==="
bash gdb-run.sh 0x42424242 wxyzUUUUUUUU gdb-w9-post.out gdb-w9-post.peer gdb-w9-post.cmd || exit 1
bash gdb-run.sh 0x11111111 wxyzAAAAAAAA gdb-w9-post-alt.out gdb-w9-post-alt.peer gdb-w9-post-alt.cmd || exit 1
echo "=== W11: wd_authkey-set probe (~23 s) ==="
bash auth-probe.sh || exit 1
bash hash-evidence.sh || exit 1

if diff -u "$BUILD/expected-hashes.txt" "$HERE/EVIDENCE_HASHES.txt"; then
    echo "WITNESS REPLAY PASS: 11 normalized hashes match; build log $BUILD/build.log"
else
    echo "WITNESS REPLAY FAIL: hash diff above; build log $BUILD/build.log" >&2
    exit 1
fi
