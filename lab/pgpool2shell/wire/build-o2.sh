#!/bin/bash
# Build both pinned pgpool tarballs at -O2 for the W2 wire hypothesis. Same
# hash-verified sources as lab/frontier/pgpool2shell/harness/run.sh; only
# CFLAGS change (that harness uses -g -O0 -fno-omit-frame-pointer).
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$(cd "$HERE/../../frontier/pgpool2shell/src" && pwd)"
WORK="${TMPDIR:-/tmp}/w2-pgpool-o2"

cd "$SRC"
sha256sum -c SHA256SUMS >/dev/null
cd "$HERE"
mkdir -p "$WORK"

for ver in 4.7.2 4.7.3; do
    if [ ! -d "$WORK/pgpool-II-$ver" ]; then
        tar -xzf "$SRC/pgpool-II-$ver.tar.gz" -C "$WORK"
    fi
    cd "$WORK/pgpool-II-$ver"
    ./configure --prefix="$WORK/inst-$ver" >/dev/null
    make -j4 CFLAGS="-g -O2 -fno-omit-frame-pointer" LDFLAGS="" >/dev/null 2>&1
    echo "O2 build ready: $(pwd)/src/pgpool"
    sha256sum src/pgpool src/watchdog/watchdog.o
done
