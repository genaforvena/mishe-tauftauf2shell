#!/usr/bin/env bash
# Live loopback replay of GHSA-5gm5-wj62-p234 against stock OpenSIPS.
# Usage: bash run-live.sh <build-dir> <label>
# Starts one receiver bound to 127.0.0.1 only, sends one crafted stanza,
# records wire bytes and the daemon's stderr, then stops the process group.
set -u
here=$(cd "$(dirname "$0")" && pwd)
build=$1
label=$2
abs=$(cd "$here/$build" && pwd)
ev="$here/evidence"
mkdir -p "$ev"
cfg="$ev/opensips-$label.cfg"

sed "s|MPATH|$abs/modules|" "$here/opensips-xmpp.cfg.template" > "$cfg"
"$abs/opensips" -c -f "$cfg" > "$ev/check-$label.log" 2>&1
echo "CONFIG_CHECK label=$label rc=$?"

if command -v ss >/dev/null && ss -ltn | grep -q ':5269 '; then
  echo "PORT_BUSY label=$label"; exit 2
fi

ASAN_OPTIONS='detect_leaks=0:abort_on_error=0:halt_on_error=1:log_path=stderr:symbolize=1' \
  setsid "$abs/opensips" -F -f "$cfg" -w "$abs" > "$ev/daemon-$label.log" 2>&1 &
pgid=$!
for i in $(seq 1 40); do
  if python3 -c 'import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(("127.0.0.1",5269))==0 else 1)'; then
    break
  fi
  sleep 0.25
done
python3 -c 'import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(("127.0.0.1",5269))==0 else 1)'
echo "LISTEN label=$label rc=$?"
python3 "$here/send_stanza.py" ${3:-} > "$ev/wire-$label.log" 2>&1
echo "WIRE_RC label=$label rc=$?"
sleep 2
kill -TERM -- "-$pgid" 2>/dev/null || true
sleep 1
kill -KILL -- "-$pgid" 2>/dev/null || true
wait "$pgid" 2>/dev/null
echo "DAEMON_RC label=$label rc=$?"
echo "--- daemon log ($label) ---"
cat "$ev/daemon-$label.log"
echo "--- wire log ($label) ---"
cat "$ev/wire-$label.log"
