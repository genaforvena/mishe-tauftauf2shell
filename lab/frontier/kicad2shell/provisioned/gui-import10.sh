#!/bin/bash
# W184: drive a fixed-build KiCad 10.0.8 Symbol Editor import of a .SchLib
# under Xvfb. Dialogs observed on this host: a webview Chrome-terms page
# (declined, never accepted), the first-run wizard (Next x4), a wxPython
# version notice (OK), then the same menu sequence as gui-import.sh (8.0.8).
# Usage: gui-import10.sh <tag> <absolute-or-relative-SchLib-path> [gdb]
set -u
TAG="$1"; FILE="$2"; MODE="${3:-plain}"
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/kicad2shell
P="$BASE/provisioned"
DISP=":14$(( $(date +%s) % 80 ))"
L="$P/apt-kicad/usr/lib/x86_64-linux-gnu:$P/apt-kicad8/usr/lib/x86_64-linux-gnu:$P/apt-kicad10/usr/lib/x86_64-linux-gnu:$P/apt-kicad10-deps/usr/lib/x86_64-linux-gnu:$P/apt-kicad10-deps/usr/lib"
export LD_LIBRARY_PATH="$L"
export KICAD_CONFIG_HOME="$P/kicad10-config"
rm -f "$P/gui10-$TAG.log" "$P/gui10-$TAG.png" "$P/gui10-$TAG.rc"
Xvfb "$DISP" -screen 0 1280x1024x24 -nolisten tcp -ac >"$P/xvfb10-$TAG.log" 2>&1 &
XV=$!
sleep 2
export DISPLAY="$DISP"
if [ "$MODE" = gdb ]; then
  gdb -q -batch -ex run -ex 'bt 45' --args "$P/apt-kicad10/usr/bin/eeschema" >"$P/gui10-$TAG.log" 2>&1 &
else
  "$P/apt-kicad10/usr/bin/eeschema" >"$P/gui10-$TAG.log" 2>&1 &
fi
EE=$!
sleep 12
import -window root "$P/gui10-$TAG-boot.png" 2>/dev/null || true
# Decline the webview terms dialog; step through the first-run wizard.
for i in 1 2 3 4; do
  xdotool mousemove 786 725 click 1; sleep 1
  xdotool mousemove 833 734 click 1; sleep 2
done
import -window root "$P/gui10-$TAG-wizard.png" 2>/dev/null || true
# wxPython notice OK; then the 8.0.8 driver's menu/chooser sequence.
xdotool mousemove 900 495 click 1; sleep 1
import -window root "$P/gui10-$TAG-notice.png" 2>/dev/null || true
# The wizard can reappear after the notice; step through it again.
for i in 1 2 3 4; do
  xdotool mousemove 786 725 click 1; sleep 0.5
  xdotool mousemove 833 734 click 1; sleep 1.5
done
import -window root "$P/gui10-$TAG-wizard2.png" 2>/dev/null || true
decline() { xdotool mousemove 786 725 click 1; sleep 0.4; }
decline; xdotool mousemove 264 11 click 1; sleep 1
decline; xdotool mousemove 320 87 click 1; sleep 5
import -window root "$P/gui10-$TAG-symed.png" 2>/dev/null || true
decline; xdotool mousemove 60 157 click 1; sleep 1
decline; xdotool mousemove 20 11 click 1; sleep 1
decline; xdotool mousemove 60 238; sleep 1
decline; xdotool mousemove 330 239 click 1; sleep 4
decline; xdotool key ctrl+l; sleep 1
decline; xdotool type --delay 20 "$FILE"; sleep 1
decline; xdotool key Return; sleep 10
decline
import -window root "$P/gui10-$TAG.png" 2>/dev/null || true
if ! kill -0 "$EE" 2>/dev/null; then wait "$EE"; RC=$?; echo "$RC" > "$P/gui10-$TAG.rc"; echo "RC=$RC"; else echo alive > "$P/gui10-$TAG.rc"; fi
echo "TAG=$TAG FILE=$FILE MODE=$MODE DISPLAY=$DISP EE=$EE"
ps -p "$EE" -o pid,stat,wchan:20,etime 2>/dev/null || echo "EE_GONE"
echo "--- log tail:"
tail -60 "$P/gui10-$TAG.log"
kill -9 "$EE" "$XV" 2>/dev/null
echo "DONE"
