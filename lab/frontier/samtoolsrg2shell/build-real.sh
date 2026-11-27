#!/bin/sh
# Rebuild four real samtools binaries from the immutable source archives.
# Public provisioning is already captured in pins/; this script uses no network.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
JOBS=${JOBS:-4}
mkdir -p runs
rm -rf work
mkdir work
tar -xzf pins/htslib.tar.gz -C work
tar -xzf pins/htscodecs.tar.gz -C work
tar -xzf pins/samtools-vuln.tar.gz -C work
tar -xzf pins/samtools-fixed.tar.gz -C work
printf '#define HTSCODECS_VERSION_TEXT "1.6.7"\n' \
    >work/htslib/htscodecs/htscodecs/version.h
(
    cd work/htslib
    autoreconf -i >../htslib-asan-autoreconf.log 2>&1
    ./configure --disable-libcurl --disable-bz2 --disable-lzma \
        --prefix="$ROOT/work/htslib-asan" \
        CFLAGS='-O0 -g -fsanitize=address -fno-omit-frame-pointer' \
        LDFLAGS='-fsanitize=address' >../htslib-asan-configure.log 2>&1
    make -j"$JOBS" >../htslib-asan-make.log 2>&1
    make install >../htslib-asan-install.log 2>&1
)

for variant in vuln fixed; do
    (
        cd "work/samtools-$variant"
        autoheader >"../samtools-$variant-asan-autoheader.log" 2>&1
        autoconf -Wno-syntax >"../samtools-$variant-asan-autoconf.log" 2>&1
        ./configure --without-curses --with-htslib="$ROOT/work/htslib-asan" \
            CFLAGS='-O0 -g -fsanitize=address -fno-omit-frame-pointer -fno-stack-protector' \
            LDFLAGS='-fsanitize=address' >"../samtools-$variant-asan-configure.log" 2>&1
        make -j"$JOBS" samtools >"../samtools-$variant-asan-make.log" 2>&1
        cp samtools "$ROOT/runs/samtools-$variant-asan"
    )
done

(
    cd work/htslib
    make distclean >../htslib-plain-distclean.log 2>&1
    ./configure --disable-libcurl --disable-bz2 --disable-lzma \
        --prefix="$ROOT/work/htslib-plain" \
        CFLAGS='-O0 -g -fno-omit-frame-pointer' >../htslib-plain-configure.log 2>&1
    make -j"$JOBS" >../htslib-plain-make.log 2>&1
    make install >../htslib-plain-install.log 2>&1
)

for variant in vuln fixed; do
    (
        cd "work/samtools-$variant"
        make distclean >"../samtools-$variant-plain-distclean.log" 2>&1
        ./configure --without-curses --with-htslib="$ROOT/work/htslib-plain" \
            CFLAGS='-O0 -g -fno-omit-frame-pointer -fno-stack-protector -fno-pie' \
            LDFLAGS='-no-pie' >"../samtools-$variant-plain-configure.log" 2>&1
        make -j"$JOBS" samtools >"../samtools-$variant-plain-make.log" 2>&1
        cp samtools "$ROOT/runs/samtools-$variant-plain"
    )
done

sha256sum runs/samtools-vuln-asan runs/samtools-fixed-asan \
    runs/samtools-vuln-plain runs/samtools-fixed-plain >runs/BINARY_SHA256.txt
printf 'BUILD_REAL_OK 4 binaries\n'
