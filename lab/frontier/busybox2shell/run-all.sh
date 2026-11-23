#!/bin/sh
# Full loopback replay. All sockets bind 127.0.0.1 only.
set +e
cd "$(dirname "$0")" || exit 1
echo "=== CLOCK $(date -u)"
echo "=== PINS"
sha256sum busybox-1.37.0.tar.bz2 \
  vuln-tftp.c fixed-tftp.c fix.patch busybox.config \
  busybox-asan busybox-fixed busybox-plain
echo "=== 1 ATTACK VULNERABLE ASAN (expect ASan WRITE of size 516)"
python3 malicious_tftp.py ./busybox-asan attack 64
echo "=== 2 SAFE OACK CONTROL (expect rc 0, no ASan)"
python3 malicious_tftp.py ./busybox-asan oack 64
echo "=== 3 SAFE DEFAULT-BLKSIZE CONTROL (expect rc 0, no ASan)"
python3 malicious_tftp.py ./busybox-asan default -
echo "=== 4 FIXED BUILD SAME ATTACK (expect no ASan)"
python3 malicious_tftp.py ./busybox-fixed attack 64
echo "=== 5 PLAIN BUILD GDB CHOSEN BYTES (expect MISHE-OOTAUFTAUF at rbuf+68)"
python3 gdb_chosen.py ./busybox-plain
echo "=== DONE $(date -u)"
