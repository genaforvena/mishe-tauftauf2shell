#!/bin/bash
# Reproduce the TLS-protocol path to CVE-2026-93475 on all three controls.
# In-process RAM transport only; no host sockets, no external traffic.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

for spec in "vuln " "fixed " "vuln safe"; do
  set -- $spec
  VER=$1; SAFE=${2:-}
  bash build.sh "$VER" $SAFE
  BIN="tls_${VER}${SAFE:+_safe}_asan"
  TAG="${VER}${SAFE:+_safe}"
  timeout 30 ./$BIN > "run-$TAG.txt" 2>&1 || true
  echo "=== $TAG ==="
  grep -E "AddressSanitizer|SUMMARY" "run-$TAG.txt" | head -3 || echo "no ASan report"
done
