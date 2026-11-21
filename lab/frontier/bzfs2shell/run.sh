#!/usr/bin/env bash
# Replay driver for the BZFlag bzfs TCP-length-overrun extracted harness.
# All sockets are AF_UNIX socketpairs created in-process; no external contact.
set -euo pipefail
cd "$(dirname "$0")"

CXX=${CXX:-g++}
CFLAGS=(-std=c++17 -O1 -g -Wall -Wextra)
OUT=${1:-out}
mkdir -p "$OUT"

$CXX "${CFLAGS[@]}" -o "$OUT/tcp_len_overflow" tcp_len_overflow.cpp
$CXX "${CFLAGS[@]}" -fsanitize=address -fno-omit-frame-pointer \
    -o "$OUT/tcp_len_overflow_asan" tcp_len_overflow.cpp

# Rungs 1, 2 and 4 plus both fixed controls, non-ASan build.
"$OUT/tcp_len_overflow" all >"$OUT/nonasan_all.txt"

# Rung 3 needs ASan: the second recv writes 64 bytes 16B before the object.
set +e
"$OUT/tcp_len_overflow_asan" rung3 >"$OUT/asan_rung3.txt" 2>&1
R3_RC=$?
set -e
if [ "$R3_RC" -eq 0 ]; then
    echo "FAIL: ASan rung3 did not abort (rc 0)" >&2
    exit 1
fi

# ASan clean controls: fixed rung3 and the intra-object chosen-value control.
"$OUT/tcp_len_overflow_asan" fixed-rung3 >"$OUT/asan_fixed_rung3.txt" 2>&1
"$OUT/tcp_len_overflow_asan" rung4 >"$OUT/asan_rung4.txt" 2>&1
"$OUT/tcp_len_overflow_asan" fixed-rung4 >"$OUT/asan_fixed_rung4.txt" 2>&1

fail=0
expect() { # file, pattern, label
    if grep -Fq -- "$2" "$1"; then
        echo "PASS $3"
    else
        echo "FAIL $3 (missing '$2' in $1)" >&2
        fail=1
    fi
}
refuse() { # file, pattern, label
    if grep -Fq -- "$2" "$1"; then
        echo "FAIL $3 (unexpected '$2' in $1)" >&2
        fail=1
    else
        echo "PASS $3"
    fi
}

A="$OUT/nonasan_all.txt"
expect "$A" 'FAILURES=0 rc=0' 'all checks pass'
expect "$A" 'R1 status=1 tcplen=-1024' 'rung1 chosen negative read offset'
expect "$A" 'rung1 last four body bytes are the chosen overwrite value' 'rung1 chosen bytes past the 1024B array'
expect "$A" 'R1FIXED status=2 tcplen=4 recv_calls=1' 'rung1 fixed control'
expect "$A" 'R2 tcplen=-1024 dst_from_object=-936 next_recv_len=1028' 'rung2 invariant failure and inflated next read'
expect "$A" 'rung2 fixed performed no recv on rejected inputs' 'rung2 fixed guard'
expect "$A" 'R4 second_status=1 recv_calls=1 dst_from_object=0' 'rung4 chosen destination at object member'
expect "$A" 'rung4 chosen marker1 read back byte-exact from the ares member' 'rung4 marker1 readback'
expect "$A" 'rung4 chosen marker2 read back byte-exact from the info member' 'rung4 marker2 readback'
expect "$A" 'rung4 fixed control leaves the preceding member untouched' 'rung4 fixed control'

R3="$OUT/asan_rung3.txt"
expect "$A" 'R2FIXED neg=4 over=4 longlen=4 recv_calls=0' 'rung2 fixed guard rejects all inputs'
expect "$R3" 'in traced_recv' 'rung3 ASan frame in harness recv wrapper'
expect "$R3" 'in receive_msg' 'rung3 ASan frame in the mirrored receive()'
refuse "$R3" 'non-ASan build must not be used' 'rung3 reached the ASan build'

for f in asan_fixed_rung3 asan_rung4 asan_fixed_rung4; do
    refuse "$OUT/$f.txt" 'ERROR: AddressSanitizer' "$f clean under ASan"
    expect "$OUT/$f.txt" 'FAILURES=0 rc=0' "$f checks pass"
done

# Determinism: two five-run groups must each produce one digest.
for mode in all; do
    : >"$OUT/det_${mode}.txt"
    for i in 1 2 3 4 5; do
        "$OUT/tcp_len_overflow" "$mode" >>"$OUT/det_${mode}.txt"
    done
done
DET=$(sha256sum "$OUT/det_all.txt" | cut -d' ' -f1)
echo "sha256_5runs=$DET"

if [ "$fail" -ne 0 ]; then
    echo "ALL CHECKS FAILED" >&2
    exit 1
fi
echo "ALL CHECKS PASS rc 0"
