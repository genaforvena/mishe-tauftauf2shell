#!/usr/bin/env bash
# Provision pinned Ruby affected/fixed sources, fix patch and glibc malloc.c.
# Fetch + sha256 verification only; no probes. Safe to re-run.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEST="$ROOT/lab/src"
mkdir -p "$DEST"
cd "$DEST"
fetch() {
  name="$1"; sha="$2"; url="$3"
  if [ ! -f "$name" ]; then
    curl -fsSL --retry 2 --max-time 600 -o "$name" "$url"
  fi
  echo "$sha  $name" | sha256sum -c -
}
fetch ruby-3.4.12.tar.xz db6c147940d7ad0b706823d42c8e6713c36dec70a1f83f635f1d3a7f0599ec90 \
  https://cache.ruby-lang.org/pub/ruby/3.4/ruby-3.4.12.tar.xz
fetch ruby-3.4.13.tar.xz 6474dff9c02ea685fc44877a4807a27366bf109b176dad182108bb8c96d09589 \
  https://cache.ruby-lang.org/pub/ruby/3.4/ruby-3.4.13.tar.xz
fetch ruby-fix-d582f8f.patch 391b34b276fbfd1532d1ad096472af5735b5dd798cc7c3a5102e0b9f8871847a \
  https://github.com/ruby/ruby/commit/d582f8f.patch
fetch glibc-2.39-malloc.c b89f737bd84d6be0dce69a7df76e8f2cf151668d434fa5ca9d634d9333e10f72 \
  'https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=malloc/malloc.c;hb=refs/heads/release/2.39/master'
echo "ruby provisioning verified"
