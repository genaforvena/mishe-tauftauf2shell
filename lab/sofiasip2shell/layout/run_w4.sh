#!/usr/bin/env bash
# W4: free-tcache next-pointer poisoning experiment for CVE-2026-116791.
# Loopback only; pinned .inc files are verbatim and hash-checked.
set -u
cd "$(dirname "$0")" || exit 2
HERE=$PWD
FNS_DIR=$HERE/../../frontier/sofiasip2shell/harness
EVID=$HERE/evidence/w4
mkdir -p "$EVID"

want17=b96477e02ac1975ed7b3305a0110271dd0f91484334c0cd6f5ec4372b674ee80
want18=42dce55f8298e1380eb955311e7163db58dc05c9c2d2d8fa1a7a4674e11b28f8
got17=$(sha256sum "$FNS_DIR/fns-1.13.17.inc" | cut -d' ' -f1)
got18=$(sha256sum "$FNS_DIR/fns-1.13.18.inc" | cut -d' ' -f1)
if [ "$got17" != "$want17" ] || [ "$got18" != "$want18" ]; then
  echo "FATAL: pinned fns hash mismatch ($got17 $got18)" >&2
  exit 2
fi

CC=${CC:-gcc}
CFLAGS='-O0 -g -fno-omit-frame-pointer -Wall -DPLAIN_MODE'
INC="-I$FNS_DIR"
$CC $CFLAGS -DPIN='"v1.13.17"' -DFNS='"fns-1.13.17.inc"' $INC \
  tcache_layout.c -o tcache-v17 || exit 2
$CC $CFLAGS -DPIN_FIXED -DPIN='"v1.13.18"' -DFNS='"fns-1.13.18.inc"' $INC \
  tcache_layout.c -o tcache-f18 || exit 2

run() { # tag binary mode [bbuflen]
  local tag=$1 bin=$2 mode=$3
  if [ $# -ge 4 ]; then
    ./"$bin" "$mode" "$4" >"$EVID/$tag.out" 2>"$EVID/$tag.err"
  else
    ./"$bin" "$mode" >"$EVID/$tag.out" 2>"$EVID/$tag.err"
  fi
  echo $? >"$EVID/$tag.rc"
  echo "=== $tag rc=$(cat "$EVID/$tag.rc") ==="
  grep -E 'GEOM |NEXT_|TARGET|MASK|NWRITE|POSTCALL|POISON|PTR[12]=|KEY_|RESULT|PIN_FIXED|SCRATCH|NO_TARGET|corrupt|detected' \
    "$EVID/$tag.err" | head -40
}

run v17-geom  tcache-v17 geom
run v17-realloc tcache-v17 realloc
run v17-short tcache-v17 short
run f18-geom  tcache-f18 geom
run f18-realloc tcache-f18 realloc
run f18-short tcache-f18 short

echo "--- summary ---"
for t in v17-geom v17-realloc v17-short f18-geom f18-realloc f18-short; do
  printf '%-14s rc=%s\n' "$t" "$(cat "$EVID/$t.rc")"
done
