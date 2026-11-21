#!/bin/sh
# Usage: ./run-asan.sh <perl-binary> <label>
set -u
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/perl2shell
PERL=$1
LABEL=$2
OUT=$BASE/evidence-$LABEL.txt
echo "RUN $(date -u) binary=$PERL label=$LABEL" > "$OUT"
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:allocator_may_return_null=1 \
  timeout 180 "$PERL" -I"$BASE/perl-5.45.1/lib" "$BASE/repro.pl" >> "$OUT" 2>&1
STATUS=$?
echo "STATUS $STATUS" >> "$OUT"
# Normalise PIDs, addresses and object paths before hashing the trace.
sed -E 's/0x[0-9a-fA-F]+/0xADDR/g; s/\[[0-9]+\]/[PID]/g; s#/home/mesh-home/[^ ]*/#PATH/#g' "$OUT" \
  | sha256sum | sed "s|-|TRACE_HASH $LABEL|" >> "$OUT"
echo "EVIDENCE $OUT"
