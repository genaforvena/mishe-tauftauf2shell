#!/usr/bin/env bash
# Real-allocator 64 KiB layout test for CVE-2026-116791.
# Uses frontier's verbatim pinned function slices; no network beyond loopback.
set -u
cd "$(dirname "$0")" || exit 2
HERE=$PWD
FNS_DIR=$HERE/../../frontier/sofiasip2shell/harness
EVID=$HERE/evidence
mkdir -p "$EVID"

# Re-assert the function slices are the frontier-verified verbatim files.
for pin in 1.13.17 1.13.18; do
  case $pin in
    1.13.17) want=b96477e02ac1975ed7b3305a0110271dd0f91484334c0cd6f5ec4372b674ee80 ;;
    1.13.18) want=42dce55f8298e1380eb955311e7163db58dc05c9c2d2d8fa1a7a4674e11b28f8 ;;
  esac
  got=$(sha256sum "$FNS_DIR/fns-$pin.inc" | cut -d' ' -f1)
  if [ "$got" != "$want" ]; then
    echo "FATAL: fns-$pin.inc hash mismatch ($got)" >&2
    exit 2
  fi
done

CC=${CC:-gcc}
CFLAGS='-O0 -g -fno-omit-frame-pointer -Wall'
INC="-I$FNS_DIR"

# asan-v17: vulnerable pin, ASan, vuln+safe cases
$CC $CFLAGS -fsanitize=address -DPIN='"v1.13.17"' -DFNS='"fns-1.13.17.inc"' $INC real_layout.c -o asan-v17 || exit 2
# asan-f18: fixed pin (+1 allocation), ASan
$CC $CFLAGS -fsanitize=address -DPIN_FIXED -DPIN='"v1.13.18"' -DFNS='"fns-1.13.18.inc"' $INC real_layout.c -o asan-f18 || exit 2
# plain-v17: vulnerable pin, plain readback
$CC $CFLAGS -DPLAIN_MODE -DPIN='"v1.13.17"' -DFNS='"fns-1.13.17.inc"' $INC real_layout.c -o plain-v17 || exit 2
# plain-f18: fixed pin (+1 allocation), plain readback
$CC $CFLAGS -DPLAIN_MODE -DPIN_FIXED -DPIN='"v1.13.18"' -DFNS='"fns-1.13.18.inc"' $INC real_layout.c -o plain-f18 || exit 2

run() { # tag binary mode
  local tag=$1 bin=$2 mode=$3
  ( ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./"$bin" "$mode" >"$EVID/$tag.out" 2>"$EVID/$tag.err"; echo $? >"$EVID/$tag.rc" )
  echo "=== $tag (rc=$(cat "$EVID/$tag.rc")) ==="
  cat "$EVID/$tag.out"
  grep -E 'PRECALL|PIN=|BEFORE|AFTER|META_OFF|XOR_DELTA|CONTROL=|ERROR: AddressSanitizer|READ of size|[0-9]+ bytes after|ws_read_frame|corrupted top size' "$EVID/$tag.err" | head -16
}

run asan-v17-vuln  asan-v17 vuln
run asan-v17-safe  asan-v17 safe
run asan-f18-vuln  asan-f18 vuln
run plain-v17-vuln plain-v17 vuln
run plain-v17-safe plain-v17 safe
run plain-f18-vuln plain-f18 vuln
run plain-v17-abort plain-v17 abort

echo "--- summary ---"
for t in asan-v17-vuln asan-v17-safe asan-f18-vuln plain-v17-vuln plain-v17-safe plain-f18-vuln plain-v17-abort; do
  printf '%-16s rc=%s\n' "$t" "$(cat "$EVID/$t.rc")"
done
