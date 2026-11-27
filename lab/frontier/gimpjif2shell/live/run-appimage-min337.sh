#!/usr/bin/env bash
# W337: one bounded no-shim GDB replay of the minimal-geometry JIF
# (33025x65026, alpha data_size=4). Not a repeat of the published-geometry
# live runs: this changes the `indexes` allocation from a 264-byte usable
# chunk to a 4-byte chunk, so the zlib OOB region abuts different heap
# objects. Ceiling: any dereference/watch hit must be measured, not inferred.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(cd "$HERE/.." && pwd)"
WORK="${GIMPJIF_APPIMAGE_WORK:-/tmp/gimpjif-appimage-w316}"
IMG="$WORK/GIMP-3.2.8-x86_64.AppImage"
ROOT="$WORK/squashfs-root"
APPRUN="$ROOT/AppRun.min337"
EVID="$HERE/evidence"
JIF="$EVID/w337-min-4d.jif"
OUT="${GIMPJIF_W337_OUT:-$EVID/w337-min-full.log}"
LOG="/tmp/w337-min-$$.log"
mkdir -p "$EVID"
if [ ! -f "$IMG" ] || [ ! -f "$WORK/SHA256SUMS" ] || [ ! -x "$ROOT/AppRun" ]; then
  echo "provision the SHA256-verified GIMP 3.2.8 AppImage first" >&2
  exit 1
fi
(cd "$WORK" && grep 'GIMP-3.2.8-x86_64.AppImage' SHA256SUMS | sha256sum -c -)
[ -f "$JIF" ] || { echo "missing $JIF" >&2; exit 1; }
sha256sum "$JIF" "$HERE/gdb-min337.cmd"

# Regenerate a private AppRun with every gimpjif2shell shim line deleted;
# the default /tmp/gimpjif-appimage AppRun preloads patch-shim.so and would
# make this a shim-assisted run, not live no-shim evidence.
: > "$APPRUN"
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    *gimpjif2shell/live/*shim.so*) continue ;;
  esac
  printf '%s\n' "$line" >> "$APPRUN"
done < "$ROOT/AppRun"
chmod +x "$APPRUN"
! grep -q 'gimpjif2shell/live/.*shim.so' "$APPRUN"

home="$(mktemp -d /tmp/gimpjif-min337-XXXXXX)"
(cd "$ROOT" && exec setsid timeout -k 5 150 env HOME="$home" \
    W337_LOG="$LOG" \
    GIMP_PLUGIN_DEBUG_WRAP=file-gif-load,run \
    GIMP_PLUGIN_DEBUG_WRAPPER="gdb -q -batch -x $HERE/gdb-min337.cmd --args" \
    ./AppRun.min337 -i --batch-interpreter plug-in-script-fu-eval \
    -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$JIF\" \"w337-min-4d.jif\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
    -b '(gimp-quit 0)') > "$OUT" 2>&1 &
runpid=$!
wait "$runpid" || true
kill -9 -- "-$runpid" 2>/dev/null || true

grep -q 'W337 PRE avail=0x80000002' "$OUT" && echo "PASS: pinned inflate reached" || echo "FAIL: no pinned inflate"
grep -q 'W337 SIGNAL' "$OUT" && echo "PASS: fault captured in GDB" || echo "INFO: no in-GDB fault stop"
echo "--- probe log ---"
cat "$LOG" 2>/dev/null || true
echo "--- tail ---"
grep -E 'W337 |Plug-in crashed|Fatal signal' "$OUT" | tail -40
sha256sum "$OUT" "$LOG" 2>/dev/null || true
