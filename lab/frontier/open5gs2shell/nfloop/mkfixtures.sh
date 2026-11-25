#!/bin/sh
# Reproduce the exact bodies used by the harness at the real SBI caller.
set -eu
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
OUT=$HERE/fixtures
mkdir -p "$OUT"

# Staged 394-byte post-preamble body: framing + 128 x 00 0d 0a.
{
    printf '\r\na:\r\n\r\n\r\n'
    i=0
    while [ "$i" -lt 128 ]; do printf '\000\015\012'; i=$((i + 1)); done
} > "$OUT/staged-394.bin"

# Attack body: one extra leading CRLF, consumed as preamble by the real
# caller, which then derives an empty boundary from the next CRLF.
{
    printf '\r\n'
    cat "$OUT/staged-394.bin"
} > "$OUT/attack-396.bin"

# Safe body: framing only, no periodic overflow bytes.
printf '\r\na:\r\n\r\n\r\n' > "$OUT/safe-10.bin"

# Counterexample: same length and framing, non-periodic bytes. The empty
# boundary state machine stops matching and must not fault the NF.
{
    printf '\r\n'
    printf '\r\na:\r\n\r\n\r\n'
    printf 'ABC%.0s' $(seq 1 128)
} > "$OUT/abc-396.bin"

wc -c "$OUT"/*.bin
sha256sum "$OUT"/*.bin
