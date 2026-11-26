#!/usr/bin/env bash
# One-command replay of the W237 real-libxml2 consumer-boundary probe.
# Builds real v2.15.3 from the pinned tarball, then exercises the public
# dictionary API with a safe QName, an INT_MAX/2+2 local name and parser names
# just past both XML parser length caps. No 4 GiB resident buffer is needed.
set -u
cd "$(dirname "$0")"

TARBALL=src/libxml2-v2.15.3.tar.gz
EXPECT_SHA=0da50c1415f4ec0364569d2119b1436ba837b31df44af28569d234272c23cf1f
got=$(sha256sum "$TARBALL" | cut -d' ' -f1)
if [ "$got" != "$EXPECT_SHA" ]; then
    echo "FAIL tarball sha256 $got"
    exit 1
fi
echo "PASS tarball sha256 $got"

if [ ! -f build/libxml2.a ]; then
    rm -rf libxml2-v2.15.3 build
    tar xzf "$TARBALL" || exit 1
    cmake -S libxml2-v2.15.3 -B build \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
        -DLIBXML2_WITH_TESTS=OFF -DLIBXML2_WITH_PYTHON=OFF \
        -DLIBXML2_WITH_ICONV=OFF -DLIBXML2_WITH_LZMA=OFF \
        -DLIBXML2_WITH_ZLIB=OFF > configure.log 2>&1 || exit 1
    cmake --build build -j4 > build.log 2>&1 || exit 1
fi
echo "PASS real libxml2 v2.15.3 static build"

gcc -O2 -I libxml2-v2.15.3/include -I build -o probe probe.c \
    build/libxml2.a -lm -ldl -lpthread 2> compile-probe.log || exit 1
gcc -O2 -I libxml2-v2.15.3/include -I build -o parser-probe parser-probe.c \
    build/libxml2.a -lm -ldl -lpthread 2> compile-parser-probe.log || exit 1
echo "PASS probes compile clean"

mkdir -p evidence
./probe safe > evidence/real-safe.log 2>&1 || exit 1
./probe over > evidence/real-over.log 2>&1 || exit 1
./parser-probe > evidence/real-parser.log 2>&1 || exit 1
cat evidence/real-safe.log evidence/real-over.log evidence/real-parser.log

fail=0
check() {
    if grep -qF "$1" "$2"; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi
}
check 'MODE=safe PREFIX_LEN=15 NAME_LEN=16 WRAP32=32 RET=non-NULL' evidence/real-safe.log
check 'MODE=over PREFIX_LEN=15 NAME_LEN=1073741825 WRAP32=1073741841 RET=NULL SECS=' evidence/real-over.log
check 'NAME_LEN=50001 HUGE=0 DOC=NULL' evidence/real-parser.log
check 'NAME_LEN=10000001 HUGE=1 DOC=NULL' evidence/real-parser.log
if [ "$fail" -eq 0 ]; then
    echo "REAL REPLAY PASS"
    exit 0
fi
echo "REAL REPLAY FAIL"
exit 1
