#!/usr/bin/env bash
# Replay the real query_graph tool-path claim from a clean checkout.
# Pinned tarballs are provisioning (fetched if absent); all tests are local.
# The only non-upstream source is the tracked grammar_zz_labstub.c in this dir.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(cd "$HERE/.." && pwd)"
cd "$BASE"

VULN=5554f8a46abf
FIX=e69e0844dbc1c737ebd3d17e97007d0f5cf16beb

for sha in "$VULN" "$FIX"; do
  if [ ! -f "pins/$sha.tar.gz" ]; then
    mkdir -p pins
    curl -fsSL "https://codeload.github.com/DeusData/codebase-memory-mcp/tar.gz/$sha" \
      -o "pins/$sha.tar.gz"
  fi
done

for sha in "$VULN" "$FIX"; do
  dir="src/codebase-memory-mcp-$sha"
  if [ ! -f "$dir/src/cypher/cypher.c" ]; then
    mkdir -p src
    tar xzf "pins/$sha.tar.gz" -C src
  fi
  cp "$HERE/grammar_zz_labstub.c" "$dir/internal/cbm/grammar_zz_labstub.c"
done
# Verify all four pins only after extraction: two hashes are cypher.c blobs
# inside the tarballs, absent from a clean checkout until now. Checking them
# earlier aborts a clean-tree replay at rc=1 before any row can run.
sha256sum -c PINS.sha256

mkdir -p "$HERE/bin" evidence
SAN="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer"
LDFLAGS="-lm -lstdc++ -lpthread -lz -fsanitize=address,undefined"
GRAMMARS="internal/cbm/grammar_c.c internal/cbm/grammar_zz_labstub.c"

build_probe() {
  local sha="$1" tag="$2" extra="$3" asanopts="$4"
  local dir="src/codebase-memory-mcp-$sha"
  # Make does not rebuild on CFLAGS_EXTRA changes; touch the source that
  # drives the final cc/link step so each configuration gets its real flags.
  touch "$dir/src/cypher/cypher.c"
  (cd "$dir" && make -j2 -f Makefile.cbm cbm \
    GRAMMAR_SRCS="$GRAMMARS" \
    CFLAGS_EXTRA="$SAN $extra" LDFLAGS="$LDFLAGS")
  cp "$dir/build/c/codebase-memory-mcp" "$HERE/bin/$tag"
  CBM_ASAN_OPTIONS="$asanopts" python3 "$HERE/probe.py" "$HERE/bin/$tag" "$tag" \
    > "evidence/replay-mcp-tool-$tag.log" 2>&1
  echo "=== $tag ==="
  grep -E '^(BINARY|CHOSEN_LEN|CBM_CACHE_DIR|=== |RC=|STDERR_LINES=|QUERY_[0-9]+ RC=)' \
    "evidence/replay-mcp-tool-$tag.log"
}

ROWS="${1:-vuln-asan vuln-recover fixed-asan}"
for row in $ROWS; do
  case "$row" in
    vuln-asan)  build_probe "$VULN" vuln-asan  ""                      "detect_leaks=0" ;;
    vuln-recover) build_probe "$VULN" vuln-recover "-fsanitize-recover=address" "detect_leaks=0:halt_on_error=0" ;;
    fixed-asan) build_probe "$FIX"  fixed-asan ""                      "detect_leaks=0" ;;
    *) echo "unknown row: $row" >&2; exit 2 ;;
  esac
done

echo "logs: evidence/replay-mcp-tool-{vuln-asan,vuln-recover,fixed-asan}.log"
