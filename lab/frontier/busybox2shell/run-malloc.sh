#!/bin/sh
# Replay of the corrupted-top-size guard/landing experiment. Loopback only:
# the stock plain BusyBox client connects to a server on 127.0.0.1.
set +e
cd "$(dirname "$0")" || exit 1
echo "=== CLOCK $(date -u)"
echo "=== PINS"
sha256sum vuln-tftp.c fixed-tftp.c busybox.config busybox-plain \
  heap_probe.py malloc_probe.py run-malloc.sh
echo "=== 1 GUARD SWEEP (RC -6 = glibc abort; values above 0x21000 abort)"
for v in 0x4141414141414141 0xffffffffffffffff 0x22000 0x21008 \
         0x21007 0x21000 0x20000 0x10000 0x21 0x20cb1; do
  printf 'TOP_SIZE=%s ' "$v"
  timeout 60 python3 heap_probe.py ./busybox-plain attack "$v" 2>&1 \
    | grep -E '^MODE |corrupted top size|sysmalloc' | tr '\n' ' '
  echo
done
echo "=== 2 MALLOC LANDING under gdb (DELTA is bytes from rbuf)"
for v in 0x20000 0x10000 0x20cb1; do
  timeout 90 python3 malloc_probe.py ./busybox-plain "$v" 2>&1 \
    | grep -E '^TOP_SIZE|GDB (FIRST|SECOND|MALLOC_CALLED|MALLOC_RET|#[0-3])'
done
echo "=== DONE $(date -u)"
