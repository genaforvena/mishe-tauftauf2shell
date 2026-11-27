#!/usr/bin/env bash
# W307: observe the file-chosen OOB store in the real GIMP 3.2.8
# file-gif-load plug-in with a read-only hardware watchpoint. The plug-in is
# launched through GIMP's documented debugger hook under a no-shim AppRun;
# no plugin word, heap byte or allocator state is modified.
#
# Asserted: the wrapped inflate call is reached, chosen bytes are stored by
# real libz past the 264-byte usable `indexes` region, and a safe JIF raises
# no watch hit. NOT asserted: a named-object write, chosen-address write,
# control flow, marker or command. Grade unchanged.
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

# Regenerate a no-shim AppRun on every replay: earlier probes leave their
# LD_PRELOAD export in the extracted AppRun, and it must not leak here.
target="$ROOT/AppRun.watch"
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

python3 "$BASE/realglib/make-jif.py" "$EVID/gdb-watch-8192.jif" published-run 8192 4d > /dev/null
ok "8 KiB chosen-run JIF written"

run_case () {
  local file="$1" out="$2"
  local home; home="$(mktemp -d /tmp/gimpjif-watchhome-XXXXXX)"
  (cd "$ROOT" && exec setsid timeout -k 5 90 env HOME="$home" \
      GIMP_PLUGIN_DEBUG_WRAP=file-gif-load,run \
      GIMP_PLUGIN_DEBUG_WRAPPER="gdb -q -batch -x $HERE/gdb-watch.cmd --args" \
      ./AppRun.watch -i --batch-interpreter plug-in-script-fu-eval \
      -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$file\" \"$(basename "$file")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
      -b '(gimp-quit 0)') > "$out" 2>&1 &
  local runpid=$!
  wait "$runpid" || true
  # Plug-in and script-fu children outlive the main AppRun; kill that run's
  # whole session only, never a global pkill.
  kill -9 -- "-$runpid" 2>/dev/null || true
}

SAFE="$BASE/realglib/evidence/safe.jif"
run_case "$SAFE" "$EVID/gdb-watch-safe.log"
run_case "$EVID/gdb-watch-8192.jif" "$EVID/gdb-watch-8192.log"

grep -q 'batch command executed successfully' "$EVID/gdb-watch-safe.log" \
  && ok "safe 4x4 JIF loads under the watchpoint debugger" || no "safe watch control"
! grep -q 'W307 OOB WATCH HIT' "$EVID/gdb-watch-safe.log" \
  && ok "safe JIF raises no watch hit" || no "safe watch hit control"

grep -q 'W307 PRE-INFLATE indexes=' "$EVID/gdb-watch-8192.log" \
  && ok "wrapped inflate call reached in the live plug-in" || no "wrapped inflate call"
grep -q 'W307 WATCH SET at' "$EVID/gdb-watch-8192.log" \
  && ok "watchpoint installed on the following chunk size word" || no "watchpoint install"
grep -q 'W307 OOB WATCH HIT at' "$EVID/gdb-watch-8192.log" \
  && ok "chosen bytes stored past the 264-byte indexes region" || no "OOB watch hit"
grep -q 'libz.so.1' "$EVID/gdb-watch-8192.log" \
  && ok "store comes from the real libz" || no "real libz frame"
grep -q ' in ReadJeffsImage ' "$EVID/gdb-watch-8192.log" \
  && ok "store backtrace reaches ReadJeffsImage" || no "ReadJeffsImage frame"
grep -q 'is_jeff_image=1' "$EVID/gdb-watch-8192.log" \
  && ok "JIF branch is on the live backtrace" || no "JIF branch frame"
grep -qE 'W307 PLUGIN SIGNAL (SIGSEGV|SIGABRT|SIGBUS)' "$EVID/gdb-watch-8192.log" \
  && ok "corrupt allocator metadata faults the live plug-in" || no "live fault"
echo "CEILING: real-libz OOB store into allocator metadata; no named-object write, chosen address, marker or command."
echo "TOTAL: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
