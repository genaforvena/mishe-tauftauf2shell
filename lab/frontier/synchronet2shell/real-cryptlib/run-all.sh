#!/usr/bin/env bash
# Real-cryptlib differential: vendored cryptlib from pinned parent 42f586d7,
# no stub getter. Builds an ASan caller and a plain caller, then runs 64-byte
# and 40-byte TERM through the verbatim one-call getter form.
set -uo pipefail
cd "$(dirname "$0")"
ROOT=../src-tree/3rdp/src/cl
LIB=$ROOT/libcl.a
INC=$ROOT/cryptlib.h
test -f "$LIB" && test -f "$INC" || { echo "MISSING_CRYPTLIB"; exit 2; }

echo "=== build real-cryptlib probe ==="
gcc -g -O0 -fsanitize=address -I"$ROOT" real_term.c "$LIB" -lpthread -o real_term_asan 2>&1 || exit 3
gcc -g -O0 -I"$ROOT" real_term.c "$LIB" -lpthread -o real_term_plain 2>&1 || exit 3

for term in 64 40; do
  echo "=== ASan real cryptlib TERM=$term ==="
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./real_term_asan "$term" 2>&1 | tee "evidence/real-asan-$term.out"
  echo "asan_rc=${PIPESTATUS[0]}"
  echo "=== plain real cryptlib TERM=$term ==="
  ./real_term_plain "$term" 2>&1 | tee "evidence/real-plain-$term.out"
  echo "plain_rc=${PIPESTATUS[0]}"
done
