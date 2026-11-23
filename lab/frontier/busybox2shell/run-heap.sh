#!/bin/sh
# Replay of the fallback/heap-metadata experiment. All sockets 127.0.0.1 only.
set +e
cd "$(dirname "$0")" || exit 1
echo "=== CLOCK $(date -u)"
echo "=== PINS"
sha256sum vuln-tftp.c fixed-tftp.c fix.patch busybox.config \
  busybox-plain busybox-fixed heap_probe.py run-heap.sh
echo "=== 1 ASLR LAYOUT x5 (rbuf varies; xbuf=rbuf-0x50; next size 0x20cb1)"
for i in 1 2 3 4 5; do python3 heap_probe.py ./busybox-plain layout | grep -E 'MODE|FIRST'; done
echo "=== 2 PLAIN ATTACK chosen top size 0x4141414141414141 (expect SIGABRT)"
python3 heap_probe.py ./busybox-plain attack 0x4141414141414141
echo "=== 3 ISOLATION original top size 0x20cb1 (expect rc 1, no abort)"
python3 heap_probe.py ./busybox-plain attack 0x20cb1
echo "=== 4 VARIANT top size 0x4242424242424242 (expect same abort)"
python3 heap_probe.py ./busybox-plain attack 0x4242424242424242
echo "=== 5 VARIANT top size 0x21 (expect glibc sysmalloc assertion)"
python3 heap_probe.py ./busybox-plain attack 0x21
echo "=== 6 CONTROL no -b 64, same 516-byte ERROR (expect rc 1, no abort)"
python3 heap_probe.py ./busybox-plain control
echo "=== 7 FIXED BUILD same attack (expect rc 1, no ASan overflow)"
python3 heap_probe.py ./busybox-fixed attack 0x4141414141414141
echo "=== 8 ATTACK UNDER GDB (metadata before/after, abort backtrace)"
python3 heap_probe.py ./busybox-plain attack-gdb
echo "=== DONE $(date -u)"
