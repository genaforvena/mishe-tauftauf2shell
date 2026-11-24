#!/usr/bin/env bash
# Provision the pinned Assimp v6.0.6 tree from the recorded tarball URL only.
# Everything else (fix hunk, harness, crafted glTF inputs) is tracked in Git.
set -euo pipefail
cd "$(dirname "$0")"
URL='https://codeload.github.com/assimp/assimp/tar.gz/refs/tags/v6.0.6'
if [ ! -f pins/assimp-6.0.6.tar.gz ]; then
  echo "fetching pinned v6.0.6 tarball" >&2
  curl -fsSL -o pins/assimp-6.0.6.tar.gz "$URL"
fi
expected='5f7ed412b76575621df0525a762b31da5874afff352b3a890c6308db4ac7204c'
actual=$(sha256sum pins/assimp-6.0.6.tar.gz | cut -d' ' -f1)
[ "$actual" = "$expected" ] || { echo "pin mismatch: $actual" >&2; exit 2; }
if [ ! -f pins/assimp-6.0.6/code/AssetLib/glTF/glTFAsset.inl ]; then
  mkdir -p pins
  tar -xzf pins/assimp-6.0.6.tar.gz -C pins
fi
sha256sum -c PINS.sha256
echo "bootstrap OK"
