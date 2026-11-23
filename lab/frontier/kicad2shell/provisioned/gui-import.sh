#!/bin/bash
# Drive a native KiCad 8.0.8 Symbol Editor import of a .SchLib under Xvfb.
# Usage: gui-import.sh <tag> <absolute-or-relative-SchLib-path> [gdb]
set -u
TAG="$1"; FILE="$2"; MODE="${3:-plain}"
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/kicad2shell
P="$BASE/provisioned"
DISP=":13$(( $(date +%s) % 80 ))"
export LD_LIBRARY_PATH="$P/apt-kicad/usr/lib/x86_64-linux-gnu:$P/apt-kicad8/usr/lib/x86_64-linux-gnu"
export PYTHONHOME="$P/apt-kicad8/usr"
export PYTHONPATH="$P/apt-kicad8/usr/lib/python3.13"
export KICAD_CONFIG_HOME="$P/kicad8-config"
rm -f "$P/gui-$TAG.log" "$P/gui-$TAG.png"
Xvfb "$DISP" -screen 0 1280x1024x24 -nolisten tcp -ac >"$P/xvfb-$TAG.log" 2>&1 &
XV=$!
sleep 2
export DISPLAY="$DISP"
if [ "$MODE" = gdb ]; then
  gdb -q -batch -ex run -ex 'bt 45' --args "$P/apt-kicad8/usr/bin/eeschema" >"$P/gui-$TAG.log" 2>&1 &
else
  "$P/apt-kicad8/usr/bin/eeschema" >"$P/gui-$TAG.log" 2>&1 &
fi
EE=$!
sleep 12
xdotool mousemove 900 495 click 1; sleep 1
xdotool mousemove 264 11 click 1; sleep 1
xdotool mousemove 320 87 click 1; sleep 5
xdotool mousemove 60 157 click 1; sleep 1
xdotool mousemove 20 11 click 1; sleep 1
xdotool mousemove 60 238; sleep 1
xdotool mousemove 330 239 click 1; sleep 4
xdotool key ctrl+l; sleep 1
xdotool type --delay 20 "$FILE"; sleep 1
xdotool key Return; sleep 10
import -window root -silent "$P/gui-$TAG.png" 2>/dev/null
echo "TAG=$TAG FILE=$FILE MODE=$MODE DISPLAY=$DISP EE=$EE"
ps -p "$EE" -o pid,stat,wchan:20,etime 2>/dev/null || echo "EE_GONE"
echo "--- log tail:"
tail -60 "$P/gui-$TAG.log"
kill -9 "$EE" "$XV" 2>/dev/null
echo "DONE"
