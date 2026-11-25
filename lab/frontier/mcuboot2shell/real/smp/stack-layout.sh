#!/bin/sh
# W5-feasibility negative: gdb dump of the real SMP process stack at the
# wire-reachable OOB offsets. Shows what the 6144/7168 writes can reach and
# where the saved return addresses actually sit. Loopback only, no external I/O.
set -eu
cd "$(dirname "$0")"
sh build.sh >/dev/null
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
LOG="$TMP/server.log"
HERE=$(pwd)
cat > "$TMP/client.sh" <<EOF
#!/bin/sh
P=\$(awk -F= '/^PORT=/{print \$2; exit}' "$LOG")
exec python3 "$HERE/client.py" "\$P" 6144
EOF
chmod +x "$TMP/client.sh"
cat > "$TMP/layout.gdb" <<EOF
set pagination off
set confirm off
break smp-host.c:123
commands
  silent
  shell sh "$TMP/client.sh" >/dev/null 2>&1 &
  continue
end
break smp-host.c:79
commands
  silent
  printf "=== WRAPPER HIT delta=%d base=%p ===\n", delta, g_buf_base
  if ! \$frames_done
    set \$frames_done = 1
    bt 5
    info frame 0
    info frame 1
    info frame 2
    info frame 3
    info frame 4
  end
  if delta == 6144
    printf "-- words base+6104 .. base+6424 --\n"
    x/40gx g_buf_base+6104
  end
  if delta == 7168
    printf "-- words base+7128 .. base+7312 --\n"
    x/24gx g_buf_base+7128
  end
  continue
end
run > "$LOG"
EOF
gdb -q -batch -x "$TMP/layout.gdb" ./smp-host > evidence/stack-layout.txt 2>&1
echo "STACK_LAYOUT_DONE"
