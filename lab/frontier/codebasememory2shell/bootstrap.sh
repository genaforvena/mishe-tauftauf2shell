#!/usr/bin/env bash
# Offline replay: extract the two pinned trees, rebuild every harness and
# regenerate the evidence matrix. Requires only the tracked tarballs.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

sha256sum -c PINS.sha256

for sha in 5554f8a46abf e69e0844dbc1c737ebd3d17e97007d0f5cf16beb; do
  dir="src/codebase-memory-mcp-$sha"
  if [ ! -f "$dir/src/cypher/cypher.c" ]; then
    mkdir -p src
    tar xzf "pins/$sha.tar.gz" -C src
  fi
done

bash build.sh
bash run-all.sh
gdb -q -batch \
  -ex 'set pagination off' \
  -ex 'break cypher.c:4118' \
  -ex 'run 48 RETURN' \
  -ex 'p &func_bufs[0]' -ex 'p &func_bufs[32]' \
  -ex 'x/70bx &func_bufs[32]' \
  --args ./harness-vuln-plain 48 RETURN > evidence/gdb-chosen-bytes.out 2>&1
cat evidence/evidence.sha256
