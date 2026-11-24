#!/usr/bin/env bash
# Rebuild the pinned server with its real loopback HTTP /rpc transport and
# drive query_graph over HTTP. Row: vuln-asan | vuln-recover | fixed-asan | all.
set -euo pipefail
ROW="${1:-all}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

if [ ! -d src/codebase-memory-mcp-5554f8a46abf ]; then
  tar xzf pins/5554f8a46abf.tar.gz -C src
fi
if [ ! -d src/codebase-memory-mcp-e69e0844dbc1c737ebd3d17e97007d0f5cf16beb ]; then
  tar xzf pins/e69e0844dbc1c737ebd3d17e97007d0f5cf16beb.tar.gz -C src
fi
sha256sum -c PINS.sha256

mkdir -p /tmp/cbm-http-ui-dist
printf '<!doctype html><title>lab</title>\n' > /tmp/cbm-http-ui-dist/index.html

build_and_probe() {
  local row="$1" tree="$2" builddir="$3" port="$4" recover="$5" asanopts="$6"
  local srcdir="src/$tree"
  cp mcp-tool/grammar_zz_labstub.c "$srcdir/internal/cbm/grammar_zz_labstub.c"
  (cd "$srcdir" && bash scripts/embed-frontend.sh /tmp/cbm-http-ui-dist "build/$builddir/embedded")
  touch "$srcdir/src/cypher/cypher.c"
  local extra=''
  if [ "$recover" = 1 ]; then
    extra=' -fsanitize-recover=address'
  fi
  (cd "$srcdir" && make -j2 -f Makefile.cbm cbm \
    BUILD_DIR="build/$builddir" \
    GRAMMAR_SRCS='internal/cbm/grammar_c.c internal/cbm/grammar_zz_labstub.c' \
    UI_SRCS='src/ui/config.c src/ui/http_server.c src/ui/layout3d.c src/ui/httpd.c src/ui/embedded_assets.c' \
    CFLAGS_EXTRA="-g -O1 -fsanitize=address,undefined${extra} -fno-omit-frame-pointer" \
    LDFLAGS="-lm -lstdc++ -lpthread -lz -fsanitize=address,undefined${extra} build/$builddir/embedded/embed_index_html.o")
  python3 http-tool/probe.py "$srcdir/build/$builddir/codebase-memory-mcp" \
    "$row" "$port" evidence "$asanopts"
}

VULN=codebase-memory-mcp-5554f8a46abf
FIXED=codebase-memory-mcp-e69e0844dbc1c737ebd3d17e97007d0f5cf16beb
case "$ROW" in
  vuln-asan)    build_and_probe vuln-asan "$VULN" http-vuln-asan 19749 0 'detect_leaks=0' ;;
  vuln-recover) build_and_probe vuln-recover "$VULN" http-vuln-recover 19750 1 'detect_leaks=0:halt_on_error=0' ;;
  fixed-asan)   build_and_probe fixed-asan "$FIXED" http-fixed-asan 19751 0 'detect_leaks=0' ;;
  all)
    build_and_probe vuln-asan "$VULN" http-vuln-asan 19749 0 'detect_leaks=0'
    build_and_probe vuln-recover "$VULN" http-vuln-recover 19750 1 'detect_leaks=0:halt_on_error=0'
    build_and_probe fixed-asan "$FIXED" http-fixed-asan 19751 0 'detect_leaks=0'
    ;;
  *) echo "unknown row: $ROW" >&2; exit 2 ;;
esac
