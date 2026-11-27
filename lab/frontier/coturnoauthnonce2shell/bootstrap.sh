#!/usr/bin/env bash
# Rebuild both pinned coturn variants from the tarballs in pins/.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ASAN_CFLAGS='-O0 -g -fno-omit-frame-pointer -fsanitize=address -fno-sanitize-recover=all'
PLAIN_CFLAGS='-O0 -g -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0'

build_one() {
    local variant=$1 mode=$2 cflags=$3
    local src="$ROOT/src-$variant"
    if [[ $mode == asan ]]; then
        rm -rf -- "$src"
        mkdir -p -- "$src"
        tar xzf "$ROOT/pins/$variant.tar.gz" -C "$src" --strip-components=1
    fi
    cc $cflags -I "$src" -I "$src/client" -I "$src/apps/common" -I "$src/server" \
        "$ROOT/harness.c" \
        "$src/client/ns_turn_ioaddr.c" "$src/client/ns_turn_msg_addr.c" \
        "$src/client/ns_turn_msg.c" \
        "$src/apps/common/apputils.c" "$src/apps/common/ns_turn_utils.c" \
        "$src/apps/common/stun_buffer.c" \
        -lssl -lcrypto -levent -levent_pthreads -lm -lpthread \
        -o "$ROOT/coturn-$variant-$mode" 2> "$ROOT/build-$variant-$mode.log"
    printf 'BUILD_OK %s-%s\n' "$variant" "$mode"
}

for variant in vuln fixed; do
    build_one "$variant" asan "$ASAN_CFLAGS"
    build_one "$variant" plain "$PLAIN_CFLAGS"
done
