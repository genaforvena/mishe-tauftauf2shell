#!/bin/bash
# W172: replay the loopback wire-input lane against the pinned builds.
# Usage: run_wire.sh [EVIDENCE_DIR]
# Requires the three pinned build trees from W161 under /tmp (see
# PROVENANCE-real.md). No new libheif build is performed.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$(cd "$HERE/../src/libheif-v1.23.6" && pwd)
EV=${1:-$HERE/neighbour/evidence}
mkdir -p "$EV"

VULN_PLAIN=/tmp/libheif2shell-vuln-plain
VULN_ASAN=/tmp/libheif2shell-vuln-asan
FIXED_ASAN=/tmp/libheif2shell-fixed-asan
for B in "$VULN_PLAIN" "$VULN_ASAN" "$FIXED_ASAN"; do
  test -f "$B/libheif/libheif.a" || { echo "missing pinned build $B" >&2; exit 1; }
done

LIBS=$(printf '%s' "$(ninja -C "$VULN_PLAIN" -t commands examples/heif-enc | tail -1)" \
  | grep -o '/usr/lib[^ ]*' | tr '\n' ' ')
build() { # BUILD DRIVER [asan]
  local b=$1 out=$2 asan=${3:-}
  local flags="-std=c++17 -g -O0 -U_GNU_SOURCE"
  [ -n "$asan" ] && flags="$flags -fsanitize=address -fno-omit-frame-pointer"
  g++ $flags -I"$SRC/libheif/api" -I"$b" "$HERE/reencode_wire.cc" \
    "$b/libheif/libheif.a" $LIBS -ldl -o "$out" || exit 2
}
build "$VULN_PLAIN" "$HERE/wire-vuln-plain"
build "$VULN_ASAN" "$HERE/wire-vuln-asan" asan
build "$FIXED_ASAN" "$HERE/wire-fixed-asan" asan
g++ -std=c++17 -g -O0 -U_GNU_SOURCE -I"$SRC/libheif/api" -I"$VULN_PLAIN" \
  "$HERE/reencode_wire_interpose.cc" "$VULN_PLAIN/libheif/libheif.a" \
  $LIBS -ldl -o "$HERE/wire-interpose-plain" || exit 2

ATTACK=$HERE/neighbour/controlled-size.heif
SAFE=$HERE/evidence/reference-same-size.heif
ONEROW=/tmp/libheif-one-row.heif
python3 "$HERE/neighbour/make_one_row_sequence.py" "$ONEROW" || exit 3

run() { # label driver input extra
  local label=$1 drv=$2 inp=$3; shift 3
  ASAN_OPTIONS=detect_leaks=0 timeout 120 python3 "$HERE/neighbour/wire_client.py" \
    "$drv" "$inp" "$EV/wire-$label.heif" "$@" >"$EV/wire-$label.out" 2>&1
  echo "$label rc=$?"
}
run vuln-asan-attack "$HERE/wire-vuln-asan" "$ATTACK"
run vuln-asan-safe "$HERE/wire-vuln-asan" "$SAFE"
run fixed-attack-noleak "$HERE/wire-fixed-asan" "$ATTACK"
run vuln-attack "$HERE/wire-vuln-plain" "$ATTACK"
run interpose-retain "$HERE/wire-interpose-plain" "$ATTACK" retain
run interpose-pattern-retain "$HERE/wire-interpose-plain" "$ONEROW" retain

python3 "$HERE/neighbour/check_wire.py" "$EV" || exit 4
python3 "$HERE/neighbour/check_wire_interpose.py" "$EV" || exit 5
