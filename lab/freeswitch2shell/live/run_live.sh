#!/usr/bin/env bash
# Loopback-only live mod_xml_rpc reproduction.
# Runs FreeSWITCH inside a private network namespace (only lo exists), so the
# module's INADDR_ANY bind cannot reach any off-loopback interface.
set -u
cd "$(dirname "$0")" || exit 1
BASE=$PWD
CONF=$BASE/run/conf
PREFIX=$BASE/run/install
LOG=$BASE/logs/live
export BASE CONF PREFIX LOG
mkdir -p "$LOG" "$BASE/run/log" "$BASE/run/run" "$BASE/run/db"
MODE=${1:-exploit}; export MODE
sudo -n --preserve-env=BASE,CONF,PREFIX,LOG,MODE unshare -n bash -s <<'EOS' || exit $?
set -u
BASE="$BASE"; CONF="$CONF"; PREFIX="$PREFIX"; LOG="$LOG"; MODE="$MODE"
echo "NETNS_IFACES=$(ip -o link show | cut -d: -f2 | tr '\n' ' ')" | tee "$LOG/netns.txt"
ip -o addr show lo >> "$LOG/netns.txt"
ip link set lo up
ip route add 127.0.0.0/8 dev lo 2>/dev/null || true
"$PREFIX/bin/freeswitch" -c -nf -nonat -nosql \
  -conf "$CONF" -log "$BASE/run/log" -run "$BASE/run/run" \
  -db "$BASE/run/db" -mod "$PREFIX/mod" \
  > "$LOG/freeswitch_stdout.txt" 2>&1 &
FSPID=$!
echo "FREESWITCH_PID=$FSPID"

READY=0
for i in $(seq 1 60); do
  if ss -ltn 2>/dev/null | grep -q ':18080'; then READY=1; break; fi
  if ! kill -0 "$FSPID" 2>/dev/null; then break; fi
  sleep 1
done
echo "LISTENER_READY=$READY"
ss -ltn > "$LOG/listen.txt" 2>&1
cat "$LOG/listen.txt"

if [ "$READY" -eq 1 ]; then
  python3 "$BASE/live_client.py" 18080 "$MODE" 2>&1 | tee "$LOG/client.txt"
  sleep 2
fi

if kill -0 "$FSPID" 2>/dev/null; then
  echo "SERVER_ALIVE_AFTER_FRAME=1"
  kill -TERM "$FSPID" 2>/dev/null
  sleep 1
  kill -KILL "$FSPID" 2>/dev/null
else
  echo "SERVER_ALIVE_AFTER_FRAME=0"
fi
wait "$FSPID" 2>/dev/null
echo "SERVER_EXIT=$?"
echo '== last server stdout =='
tail -40 "$LOG/freeswitch_stdout.txt"
EOS
