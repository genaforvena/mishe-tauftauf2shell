#!/usr/bin/env bash
# Build the direct-call harness against the pinned vulnerable and fixed trees.
# Sources are the project's own cypher.c, store.c, foundation modules and
# vendored sqlite3/yyjson; only harness.c is lab-authored.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
VULN="$HERE/src/codebase-memory-mcp-5554f8a46abf"
FIX="$HERE/src/codebase-memory-mcp-e69e0844dbc1c737ebd3d17e97007d0f5cf16beb"

FOUND=(
  src/foundation/arena.c src/foundation/hash_table.c src/foundation/str_intern.c
  src/foundation/log.c src/foundation/str_util.c src/foundation/platform.c
  src/foundation/system_info.c src/foundation/slab_alloc.c src/foundation/yaml.c
  src/foundation/compat.c src/foundation/compat_thread.c src/foundation/compat_fs.c
  src/foundation/compat_regex.c src/foundation/mem.c src/foundation/diagnostics.c
  src/foundation/profile.c src/foundation/dump_verify.c src/foundation/limits.c
  src/foundation/subprocess.c
)
build() {
  local tree="$1" out="$2" san="$3" tag="$4"
  echo "BUILD $out <- $(basename "$tree") [$san]"
  (
    cd "$tree"
    # Vendored objects are compiled with the project's own relaxed flags and
    # sanitizers, exactly as Makefile.cbm's test build does.
    gcc -std=c11 -g -O1 $san -w -Ivendored/mimalloc/include -Ivendored/mimalloc/src \
      -DMI_OVERRIDE=0 -c vendored/mimalloc/src/static.c -o "$HERE/.mimalloc-$tag.o"
    gcc -std=c11 -D_DEFAULT_SOURCE -g -O1 $san -w -Iinternal/cbm \
      -Iinternal/cbm/vendored/ts_runtime/include -Iinternal/cbm/vendored/ts_runtime/src \
      -c internal/cbm/ts_runtime.c -o "$HERE/.tsruntime-$tag.o"
    gcc -std=c11 -D_DEFAULT_SOURCE -D_GNU_SOURCE -g -O1 $san \
      -fno-omit-frame-pointer -w \
      -Isrc -Ivendored -Ivendored/sqlite3 -Ivendored/mimalloc/include \
      -Iinternal/cbm -Iinternal/cbm/vendored/ts_runtime/include \
      -o "$out" "$HERE/harness.c" \
      src/cypher/cypher.c src/store/store.c "${FOUND[@]}" \
      vendored/sqlite3/sqlite3.c vendored/yyjson/yyjson.c \
      "$HERE/.mimalloc-$tag.o" "$HERE/.tsruntime-$tag.o" \
      -lm -lpthread -lz -lstdc++
  )
}

SAN="-fsanitize=address,undefined"
build "$VULN" "$HERE/harness-vuln-asan" "$SAN" vuln
build "$FIX"  "$HERE/harness-fixed-asan" "$SAN" fixed
build "$VULN" "$HERE/harness-vuln-asan-recover" "-fsanitize=address,undefined -fsanitize-recover=address" vulnrec
build "$VULN" "$HERE/harness-vuln-plain" "" plain
echo "BUILD OK"
