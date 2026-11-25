#!/bin/bash
# Replay the real-ircd ASan S2S KILL controls on 127.0.0.1 only.
# Requires the two installed ASan builds at /tmp/solanum-{vuln,fixed}-install.
set -u
cd "$(dirname "$0")" || exit 2
PEER='link.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.'
pass=0; fail=0
ok() { pass=$((pass+1)); echo "PASS $1"; }
no() { fail=$((fail+1)); echo "FAIL $1"; }

run_case() {
  name=$1; prefix=$2; conf=$3; port=$4; len=$5; expect=$6
  pkill -9 -f "$prefix/bin/solanum" 2>/dev/null
  P=$PWD
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
    "$prefix/bin/solanum" -configfile "$P/$conf" -foreground \
    -logfile "$P/$name-ircd.log" -pidfile "$P/$name.pid" \
    >"$P/$name-asan.log" 2>&1 &
  pid=$!
  sleep 3
  PEER_NAME="$PEER" PEER_SID=2AB VICTIM_NICK=v KILL_PATH=x \
    python3 peer_probe.py "$port" "$len" "$name" >"probe-$name.out" 2>&1
  probe_rc=$?
  sleep 1
  kill -9 "$pid" 2>/dev/null
  hits=$(grep -c 'AddressSanitizer' "$name-asan.log")
  delivered=$(grep -c 'QUIT :Killed' "probe-$name.out")
  relayed=$(grep -c ' KILL v :' "probe-$name.out")
  if [ "$expect" = asan ]; then
    if [ "$probe_rc" -eq 0 ] && [ "$relayed" -ge 1 ]; then ok "$name KILL reached ms_kill"; else no "$name KILL reached ms_kill (rc=$probe_rc)"; fi
  elif [ "$probe_rc" -eq 0 ] && [ "$delivered" -ge 1 ]; then ok "$name KILL delivered"; else no "$name KILL delivered (rc=$probe_rc)"; fi
  if [ "$expect" = asan ]; then
    if grep -q 'global-buffer-overflow' "$name-asan.log" &&
       grep -q 'WRITE of size 564' "$name-asan.log" &&
       grep -q 'm_kill.c:277' "$name-asan.log"; then ok "$name ASan WRITE at m_kill.c:277"; else no "$name ASan WRITE at m_kill.c:277"; fi
  else
    if [ "$hits" -eq 0 ]; then ok "$name clean (no ASan report)"; else no "$name clean ($hits reports)"; fi
  fi
}

run_case vuln-long-490 /tmp/solanum-vuln-install vuln.conf 17601 490 asan
run_case fixed-long-490 /tmp/solanum-fixed-install fixed.conf 17602 490 clean
run_case vuln-safe-420 /tmp/solanum-vuln-install vuln.conf 17601 420 clean

pkill -9 -f '/tmp/solanum-vuln-install/bin/solanum' 2>/dev/null
pkill -9 -f '/tmp/solanum-fixed-install/bin/solanum' 2>/dev/null
echo "RESULT $pass PASS / $fail FAIL"
test "$fail" -eq 0
