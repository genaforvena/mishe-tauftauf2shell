#!/bin/bash
cd /home/mesh-home/mishe-tauftauf2shell || exit 1
rm -f /tmp/pgpool-groom/gdb.out /tmp/pgpool-groom/peer.out
python3 /tmp/pgpool-groom/peer_groom.py 14 2 > /tmp/pgpool-groom/peer.out 2>&1 &
PEER=$!
timeout 70 gdb -q -batch -x /tmp/pgpool-groom/gdb_groom.cmd /tmp/w108-pgpool-replay/pgpool-II-4.7.2/src/pgpool > /tmp/pgpool-groom/gdb.out 2>&1
RC=$?
kill $PEER 2>/dev/null
wait $PEER 2>/dev/null
pkill -f 'pgpool -n -D -f lab/pgpool2shell/wire/pgpool-vuln.conf' 2>/dev/null
echo "gdb_rc=$RC"
