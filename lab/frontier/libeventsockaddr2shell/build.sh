#!/bin/bash
# Build pinned libevent sources (vulnerable 1b7cc9b5 / fixed 52057cb3) in
# ASan and production configurations, plus the advisory's server/client PoC.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
SRC="$1"          # src-vuln or src-fixed
TAG="$2"          # vuln or fixed
for BUILD in asan prod; do
    BD="$D/build-$TAG-$BUILD"
    mkdir -p "$BD"
    cd "$BD"
    case "$BUILD" in
        asan)
            CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer -DNDEBUG"
            LDFLAGS="-fsanitize=address" ;;
        prod)
            CFLAGS="-O2 -g -DNDEBUG"
            LDFLAGS="" ;;
    esac
    cmake "$D/$SRC" \
        -DEVENT__DISABLE_MBEDTLS=ON \
        -DEVENT__DISABLE_OPENSSL=ON \
        -DEVENT__DISABLE_TESTS=ON \
        -DEVENT__DISABLE_BENCHMARK=ON \
        -DEVENT__DISABLE_REGRESS=ON \
        -DEVENT__DISABLE_SAMPLES=ON \
        -DEVENT__LIBRARY_TYPE=STATIC \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_FLAGS="$CFLAGS" \
        -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" >/dev/null
    make event_core_static event_extra_static event_pthreads_static -j"$(nproc)" >/dev/null
    cc -O1 -g -DNDEBUG $LDFLAGS -I "$BD/include" -I "$D/$SRC/include" \
        -o r1_server_threaded "$D/r1_server_threaded.c" \
        lib/libevent_extra.a lib/libevent_pthreads.a lib/libevent_core.a -lpthread
done
cc -O1 -g -o "$D/build-$TAG-prod/r1_client" "$D/r1_client.c"
echo "BUILD_OK $TAG"
