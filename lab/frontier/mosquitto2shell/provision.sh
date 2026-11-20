#!/usr/bin/env bash
# Provision pinned Mosquitto sources. Mosquitto.org publishes no sha256 sidecar,
# so these local hashes pin the exact files used in the lab.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
DEST="$ROOT/lab/src"
mkdir -p "$DEST"
cd "$DEST"
fetch() {
  name="$1"; sha="$2"
  if [ ! -f "$name" ]; then
    curl -fsSL --retry 2 --max-time 300 -o "$name" "https://mosquitto.org/files/source/${name}"
  fi
  echo "$sha  $name" | sha256sum -c -
}
fetch mosquitto-2.1.2.tar.gz fd905380691ac65ea5a93779e8214941829e3d6e038d5edff9eac5fd74cbed02
fetch mosquitto-2.1.3.tar.gz 089a55bb011804e031ec822c4db9abca48102fa59343fb7aeb1b9c97bb0a3527
echo "mosquitto sources verified"
