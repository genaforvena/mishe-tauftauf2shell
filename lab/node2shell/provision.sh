#!/usr/bin/env bash
# Provision the two pinned Node prebuilts used by node2shell.
# Fetch + sha256 verification only; no probes. Safe to re-run.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEST="$ROOT/lab/node2shell/bin"
mkdir -p "$DEST"
cd "$DEST"
fetch() {
  name="$1"; sha="$2"
  if [ ! -f "$name" ]; then
    curl -fsSL --retry 2 --max-time 600 -o "$name" "https://nodejs.org/dist/v${name#node-v}/${name}"
  fi
  echo "$sha  $name" | sha256sum -c -
  case "$name" in
    *.tar.xz) [ -d "${name%.tar.xz}" ] || tar -xJf "$name" ;;
    *) echo "unsupported archive: $name" >&2; exit 2 ;;
  esac
}
fetch node-v24.22.2-linux-x64.tar.xz 48cc0e21e048790e54c0cf5749c2725005313d652651c40b7a21feb9697aaf75
fetch node-v24.22.3-linux-x64.tar.xz 4f2b175a6d53a5c617a80dba2676238a0688cef28c6da4eba35c7d844e66fcfb
echo "node prebuilts verified:"
"$DEST/node-v24.22.2-linux-x64/bin/node" --version
"$DEST/node-v24.22.3-linux-x64/bin/node" --version
