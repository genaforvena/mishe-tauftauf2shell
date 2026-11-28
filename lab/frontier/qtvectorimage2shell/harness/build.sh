#!/bin/bash
# Extract the exact index-copy block from the two pinned renderer files.
set -euo pipefail
cd "$(dirname "$0")/.."
sha256sum -c SHA256SUMS >/dev/null
mkdir -p harness/gen

extract() {
  local in="$1" out="$2"
  awk '
    /^void QQuickShapeGenericRenderer::triangulateFill\(/ {fn=1}
    fn && /^[[:space:]]*size_t indexByteSize;/ {on=1}
    /^void QQuickShapeGenericRenderer::triangulateStroke\(/ {on=0; fn=0}
    on && /^}$/ {exit}
    on {print}
  ' "$in" > "$out"
  grep -q 'memcpy(fillIndices->data(), ts.indices.data(), indexByteSize);' "$out"
}

extract src/qquickshapegenericrenderer.v6.12.0.cpp harness/gen/block.vuln.inc
extract src/qquickshapegenericrenderer.fixed.cpp harness/gen/block.fixed.inc
grep -q 'fillIndices->resize(ts.indices.size() / 2);' harness/gen/block.vuln.inc
grep -q 'fillIndices->resize((ts.indices.size() + 1) / 2);' harness/gen/block.fixed.inc

for arm in vuln fixed; do
  cp "harness/gen/block.$arm.inc" harness/gen/block.inc
  g++ -std=gnu++17 -O0 -g -fno-omit-frame-pointer -fsanitize=address \
      -I harness -I harness/gen harness/main.cpp -o "harness/gen/qtindex.$arm.asan"
  g++ -std=gnu++17 -O0 -g -fno-omit-frame-pointer \
      -I harness -I harness/gen harness/main.cpp -o "harness/gen/qtindex.$arm.plain"
done
sha256sum harness/gen/block.vuln.inc harness/gen/block.fixed.inc \
  > harness/gen/build.sha256
echo BUILD_OK
