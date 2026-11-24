#!/usr/bin/env bash
# Rebuild all harness binaries from the pinned source blobs. No network.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
VULN="$ROOT/pins/assimp-6.0.6/code/AssetLib/glTF/glTFAsset.inl"
FIXED="$ROOT/pins/fixed-6.0.6/code/AssetLib/glTF/glTFAsset.inl"

mkdir -p gen/vuln gen/fixed bin
printf '// generated from pinned v6.0.6 glTFAsset.inl; line ranges in PROVENANCE.md\n' > gen/vuln/pinned.inc
sed -n '385,402p' "$VULN" >> gen/vuln/pinned.inc   # Accessor::GetPointer
sed -n '424,449p' "$VULN" >> gen/vuln/pinned.inc   # Accessor::ExtractData
sed -n '464,477p' "$VULN" >> gen/vuln/pinned.inc   # Accessor::Indexer ctor + GetValue

printf '// generated from pinned v6.0.6 glTFAsset.inl + PR 6860 hunk\n' > gen/fixed/pinned.inc
sed -n '385,402p' "$FIXED" >> gen/fixed/pinned.inc # Accessor::GetPointer
sed -n '424,438p' "$FIXED" >> gen/fixed/pinned.inc # Accessor::CheckDataRange
sed -n '440,468p' "$FIXED" >> gen/fixed/pinned.inc # Accessor::ExtractData
sed -n '483,504p' "$FIXED" >> gen/fixed/pinned.inc # Accessor::Indexer ctor + GetValue

for target in vuln fixed; do
  for cc in g++ clang++; do
    "$cc" -std=c++17 -O0 -g -fno-omit-frame-pointer -fsanitize=address \
      -I"gen/$target" harness.cpp -o "bin/$target-$cc-asan"
  done
done
g++ -std=c++17 -O0 -g -fno-stack-protector -DPLAIN_ARENA \
  -Igen/vuln harness.cpp -o bin/vuln-plain
g++ -std=c++17 -O0 -g -fno-stack-protector -DPLAIN_ARENA \
  -Igen/fixed harness.cpp -o bin/fixed-plain
sha256sum gen/vuln/pinned.inc gen/fixed/pinned.inc bin/*
