#!/bin/bash
# Rebuild the three NSD trees and sink harnesses from pinned tarballs.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
cd "$D"

ASAN_FLAGS='-O1 -g -fsanitize=address -fno-omit-frame-pointer'
OBJS='answer.o axfr.o ixfr.o ixfrcreate.o buffer.o configlexer.o configparser.o dname.o dns.o edns.o iterated_hash.o lookup3.o namedb.o nsec3.o options.o packet.o query.o rbtree.o radtree.o rdata.o region-allocator.o rrl.o siphash.o tsig.o tsig-openssl.o udb.o util.o bitset.o popen3.o proxy_protocol.o zonec.o verify.o'
SUP='cpuset.o b64_pton.o b64_ntop.o setproctitle.o'

for tree in vuln patched plain; do
    rm -rf "$tree"
    tar xzf pins/vuln.tar.gz
    mv nsd-4.14.2 "$tree"
done
(cd patched && patch -p1 < ../pins/fix.patch)

for tree in vuln patched; do
    (cd "$tree" && ./configure CFLAGS="$ASAN_FLAGS" LDFLAGS='-fsanitize=address' \
        --disable-shared --disable-dnstap >/dev/null && make -j2 >/dev/null)
done
(cd plain && ./configure --disable-shared --disable-dnstap >/dev/null \
    && make -j2 >/dev/null)

for tree in vuln patched; do
    (cd "$tree" && gcc -I. -I./simdzone/include $ASAN_FLAGS -c ../harness.c -o harness.o \
        && gcc -O1 -g -fsanitize=address -o "../harness-$tree-asan" harness.o $OBJS $SUP \
            simdzone/libzone.a -lssl -lcrypto -levent)
done
(cd plain && gcc -I. -I./simdzone/include -O1 -g -c ../harness.c -o harness.o \
    && gcc -O1 -g -o ../harness-vuln-plain harness.o $OBJS $SUP \
        simdzone/libzone.a -lssl -lcrypto -levent)

test -x harness-vuln-asan && test -x harness-patched-asan \
    && test -x harness-vuln-plain && echo BOOTSTRAP_OK
