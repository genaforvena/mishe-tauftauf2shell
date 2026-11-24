#!/bin/sh
# W184: regenerate every tiny-MJPEG product into OUT_DIR and compare it
# byte-for-byte with the committed evidence, then check the saved case logs.
# Catches a generator that silently stops producing one of the four files.
# Usage: replay_tiny_mjpeg.sh OUT_DIR
set -eu
OUT=$1
R=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
E="$R/evidence/tiny-mjpeg"
mkdir -p "$OUT"
python3 "$R/make_tiny_mjpeg_sequence.py" "$E" "$OUT"
for f in tiny64-ref.heif tiny64-mixed.heif tiny72-ref.heif tiny72-mixed.heif; do
    cmp "$OUT/$f" "$E/$f"
done
python3 "$R/check_tiny_mjpeg.py" "$E"
echo "replay_tiny_mjpeg: OK"
