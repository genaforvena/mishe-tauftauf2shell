#!/usr/bin/env bash
# W319: replay the no-shim GDB allocation-site tracer in the SHA-verified
# GIMP 3.2.8 AppImage. No preloaded shim, no plugin or heap patch. The claim,
# if any, is only an allocation caller named for a chunk at a known offset
# after indexes; a chosen-address write, dereference, marker or command is
# never asserted by this runner.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
GDB_SCRIPT="${GDB_SCRIPT:-$HERE/gdb-allocsite2.cmd}"
BASE="$(cd "$HERE/.." && pwd)"
WORK="${GIMPJIF_APPIMAGE_WORK:-/tmp/gimpjif-appimage-w316}"
IMG="$WORK/GIMP-3.2.8-x86_64.AppImage"
ROOT="$WORK/squashfs-root"
EVID="$HERE/evidence"
mkdir -p "$EVID"

(cd "$WORK" && grep 'GIMP-3.2.8-x86_64.AppImage' SHA256SUMS | sha256sum -c -)

# Regenerate the AppRun for this run: earlier probes may have left an
# LD_PRELOAD export in the extracted workdir.
target="$ROOT/AppRun.allocsite2"
: > "$target"
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    *gimpjif2shell/live/*shim.so*) continue ;;
  esac
  printf '%s\n' "$line" >> "$target"
done < "$ROOT/AppRun"
rm -f /tmp/w319-alloc-trace.log
chmod +x "$target"
! grep -q 'gimpjif2shell/live/.*shim.so' "$target"

python3 "$BASE/realglib/make-jif.py" "$EVID/gdb-allocsite2-8192.jif" published-run 8192 4d > /dev/null

home="$(mktemp -d /tmp/gimpjif-allocsite2-home-XXXXXX)"
file="$EVID/gdb-allocsite2-8192.jif"
(cd "$ROOT" && exec setsid timeout -k 5 100 env HOME="$home" \
    GIMP_PLUGIN_DEBUG_WRAP=file-gif-load,run \
    GIMP_PLUGIN_DEBUG_WRAPPER="gdb -q -batch -x $GDB_SCRIPT --args" \
    ./AppRun.allocsite2 -i --batch-interpreter plug-in-script-fu-eval \
    -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$file\" \"$(basename "$file")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
    -b '(gimp-quit 0)') > "$EVID/w319-allocsite2.log" 2>&1 &
runpid=$!
wait "$runpid" || true
# Children outlive the main AppRun; kill only this run's session.
kill -9 -- "-$runpid" 2>/dev/null || true

[ -f /tmp/w319-alloc-trace.log ] && cp /tmp/w319-alloc-trace.log "$EVID/w319-alloc-trace.log"
cat "$EVID/w319-allocsite2.log" "$EVID/w319-alloc-trace.log" > "$EVID/w319-combined.log" 2>/dev/null || true
log="$EVID/w319-combined.log"
grep -q 'W319 PRE-INFLATE indexes=' "$log" && echo 'PASS: wrapped inflate reached' || echo 'FAIL: wrapped inflate not observed'
grep -q 'W319 WORD +272=' "$log" && echo 'PASS: allocation lookup at indexes+272 recorded' || echo 'FAIL: no +272 lookup'
grep -q 'W319 WORD +304=' "$log" && echo 'PASS: allocation lookup at indexes+304 recorded' || echo 'FAIL: no +304 lookup'
if grep -qE 'W319 WORD \+272=.*ALLOC: size=[0-9]+ caller=' "$log"; then
  echo 'PASS: +272 chunk matched a traced small allocation'
else
  echo 'NIT: +272 chunk not matched to a traced allocation'
fi
if grep -qE 'W319 WORD \+304=.*ALLOC: size=[0-9]+ caller=' "$log"; then
  echo 'PASS: +304 chunk matched a traced small allocation'
else
  echo 'NIT: +304 chunk not matched to a traced allocation'
fi
! grep -q 'SHIM_PATCH' "$log" && echo 'PASS: no shim patch line' || echo 'FAIL: shim patch in log'
echo "CEILING: allocation caller only; no chosen-address write, dereference, marker or command."
