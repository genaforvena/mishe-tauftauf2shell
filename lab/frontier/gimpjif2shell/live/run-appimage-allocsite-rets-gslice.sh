#!/usr/bin/env bash
# W321 second control: same validated malloc-return tracer, run with
# G_SLICE=always-malloc so GSlice small-object allocations pass through glibc
# malloc. W320 used broken return offsets; this run uses the seven real ret
# sites from the SHA-verified AppImage libc. Environment change is part of
# the claim; no shim, no plugin byte, no heap byte change.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(cd "$HERE/.." && pwd)"
WORK="${GIMPJIF_APPIMAGE_WORK:-/tmp/gimpjif-appimage-w316}"
ROOT="$WORK/squashfs-root"
EVID="$HERE/evidence"
mkdir -p "$EVID"
(cd "$WORK" && grep 'GIMP-3.2.8-x86_64.AppImage' SHA256SUMS | sha256sum -c -)
target="$ROOT/AppRun.retsgslice"
: > "$target"
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    *gimpjif2shell/live/*shim.so*) continue ;;
  esac
  printf '%s\n' "$line" >> "$target"
done < "$ROOT/AppRun"
chmod +x "$target"
! grep -q 'gimpjif2shell/live/.*shim.so' "$target"
file="$HERE/evidence/gdb-liveptr-8192.jif"
home="$(mktemp -d /tmp/gimpjif-retsgslice-home-XXXXXX)"
(cd "$ROOT" && exec setsid timeout -k 5 120 env HOME="$home" \
    G_SLICE=always-malloc \
    GIMP_PLUGIN_DEBUG_WRAP=file-gif-load,run \
    GIMP_PLUGIN_DEBUG_WRAPPER="gdb -q -batch -x $HERE/gdb-allocsite-rets.cmd --args" \
    ./AppRun.retsgslice -i --batch-interpreter plug-in-script-fu-eval \
    -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$file\" \"$(basename "$file")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
    -b '(gimp-quit 0)') > "$EVID/w321-allocsite-rets-gslice.log" 2>&1 &
runpid=$!
wait "$runpid" || true
kill -9 -- "-$runpid" 2>/dev/null || true
grep -E 'W321|Breakpoint|GIMP-Error|fatal error' "$EVID/w321-allocsite-rets-gslice.log" | head -60 || true
