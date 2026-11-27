#!/usr/bin/env bash
# W304: capture the live file-gif-load fault frame for the 8 KiB natural JIF
# overflow, with a no-fault safe JIF control under the identical debugger.
#
# GIMP's GIMP_PLUGIN_DEBUG_WRAP/WRAPPER hooks start only file-gif-load under
# gdb; the plugin binary shipped in GIMP 3.2.8 has debug_info. No shim is
# preloaded and no plugin word is patched. The logged fault is an allocator
# dereference attempt on corrupt metadata, NOT a successful chosen-address
# write, named-object write, marker or command. No grade change is asserted.
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
if [ ! -f "$IMG" ] || [ ! -f "$WORK/SHA256SUMS" ] || [ ! -x "$ROOT/AppRun" ]; then
  echo "provision the SHA256-verified GIMP 3.2.8 AppImage first (see run-appimage-span.sh)" >&2
  exit 1
fi
(cd "$WORK" && grep 'GIMP-3.2.8-x86_64.AppImage' SHA256SUMS | sha256sum -c -)
ok "official AppImage SHA256 verified"

python3 "$BASE/realglib/make-jif.py" "$EVID/gdb-8192.jif" published-run 8192 4d > /dev/null
ok "8 KiB chosen-run JIF written"

run_case () {
  local file="$1" out="$2"
  local home; home="$(mktemp -d /tmp/gimpjif-gdbhome-XXXXXX)"
  (cd "$ROOT" && timeout -k 5 90 env HOME="$home" \
      GIMP_PLUGIN_DEBUG_WRAP=file-gif-load,run \
      GIMP_PLUGIN_DEBUG_WRAPPER="gdb -q -batch -x $HERE/gdb-plugin.cmd --args" \
      ./AppRun -i --batch-interpreter plug-in-script-fu-eval \
      -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$file\" \"$(basename "$file")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
      -b '(gimp-quit 0)') > "$out" 2>&1 || true
  ps -u "$(id -u)" -o pid,args | grep -F "$ROOT" | grep 'org.gimp.GIMP.Stable -i' \
    | grep -v grep | awk '{print $1}' | xargs -r kill -9 || true
}

run_case "$BASE/realglib/evidence/safe.jif" "$EVID/gdb-safe.log"
run_case "$EVID/gdb-8192.jif" "$EVID/gdb-8192.log"

grep -q 'batch command executed successfully' "$EVID/gdb-safe.log" \
  && ok "safe JIF loads under the plug-in debugger" || no "safe gdb control"
! grep -q 'W304 PLUGIN SIGNAL' "$EVID/gdb-safe.log" \
  && ok "safe JIF raises no plug-in signal" || no "safe gdb signal control"

grep -Eq 'W304 PLUGIN SIGNAL (SIGSEGV|SIGABRT|SIGBUS)' "$EVID/gdb-8192.log" \
  && ok "8 KiB chosen overflow faults the live plug-in under gdb" || no "8 KiB gdb fault"
grep -q 'in malloc ()' "$EVID/gdb-8192.log" \
  && ok "fault frame is inside malloc" || no "malloc fault frame"
grep -q ' in ReadImage ' "$EVID/gdb-8192.log" \
  && ok "fault backtrace reaches ReadImage with is_jeff_image=1" || no "ReadImage backtrace frame"
grep -q 'is_jeff_image=1' "$EVID/gdb-8192.log" \
  && ok "JIF branch is on the live backtrace" || no "JIF branch frame"
echo "FAULT REGISTERS: $(grep -m1 '^rax' "$EVID/gdb-8192.log" || echo UNKNOWN)"
echo "CEILING: allocator dereference attempt only; no chosen-address write, marker or command."

echo "TOTAL: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
