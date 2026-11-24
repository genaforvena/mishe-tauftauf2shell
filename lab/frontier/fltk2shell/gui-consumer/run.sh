#!/bin/sh
# Drive the GUI consumer on a private Xvfb display; record exact commands/rc.
set -eu
cd "$(dirname "$0")"
mkdir -p outputs
rm -f commands.txt exit-codes.txt inputs.sha256 outputs/*
export ASAN_OPTIONS=abort_on_error=1:allocator_may_return_null=1

DISPLAY_NUM=177
if [ -e "/tmp/.X11-unix/X$DISPLAY_NUM" ]; then
  echo "display :$DISPLAY_NUM already in use" >&2
  exit 2
fi
Xvfb ":$DISPLAY_NUM" -screen 0 640x480x24 -nolisten tcp \
  > outputs/xvfb.log 2>&1 &
xvfb_pid=$!
trap 'kill "$xvfb_pid" 2>/dev/null || true' EXIT
i=0
while [ ! -e "/tmp/.X11-unix/X$DISPLAY_NUM" ] && [ "$i" -lt 50 ]; do
  i=$((i + 1))
  sleep 0.1
done
[ -e "/tmp/.X11-unix/X$DISPLAY_NUM" ] || { echo 'Xvfb did not start' >&2; exit 3; }
export DISPLAY=":$DISPLAY_NUM"
echo "DISPLAY=$DISPLAY" > display.txt

run_case() { # label binary safe-file second-file
  label=$1; bin=$2; safe=$3; second=$4
  cmd="./$bin $safe $second"
  printf '%s\n' "$cmd" >> commands.txt
  set +e
  $cmd > "outputs/$label.out" 2>&1
  rc=$?
  set -e
  printf '%s rc=%s\n' "$label" "$rc" >> exit-codes.txt
  printf 'COMMAND: %s\nDISPLAY: %s\nEXIT: %s\n' "$cmd" "$DISPLAY" "$rc" \
    > "outputs/$label.meta"
}

sha256sum ../poc-chosen.bmp ../safe.bmp gui.cxx > inputs.sha256
run_case vuln-crafted gui-vuln ../safe.bmp ../poc-chosen.bmp
run_case vuln-safe gui-vuln ../safe.bmp ../safe.bmp
run_case fixed-crafted gui-fixed ../safe.bmp ../poc-chosen.bmp
run_case fixed-safe gui-fixed ../safe.bmp ../safe.bmp
echo 'run OK'
