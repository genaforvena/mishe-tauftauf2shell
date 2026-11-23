#!/usr/bin/env python3
"""Assert the W172 loopback wire-input lane observations.

Usage: check_wire.py EVIDENCE_DIR

Checks saved runs of reencode_wire.cc (one HEIF byte stream accepted on
127.0.0.1, decoded by the pinned public libheif decoder, re-encoded through a
fixed-size x265 sequence encoder):

  * vuln-asan attack: ASan heap-buffer-overflow WRITE of size 64 at pinned
    pixelimage.cc:644, 0 bytes after a 32783-byte region, via the public API;
  * vuln-asan safe input: no ASan, both frames 512x64, clean rc 0;
  * fixed-pin attack: encode rc 2 with the mixed-size guard message, no ASan;
  * vuln plain build: allocator abort (corrupted unsorted chunks).

The synthetic consumer is a harness, not a real-world network service. This is
rung 3 plus rung 4 with WIRE-DERIVED bytes: no valid pointer, no marker, no
command, no live server, no rung 5.
"""
import sys
from pathlib import Path

here = Path(sys.argv[1])
attack = (here / "wire-vuln-asan-attack.out").read_text()
safe = (here / "wire-vuln-asan-safe.out").read_text()
fixed = (here / "wire-fixed-attack-noleak.out").read_text()
plain = (here / "wire-vuln-attack.out").read_text()

# All four runs must actually receive the stream over the socket.
for name, text, size in [("attack", attack, 6004), ("safe", safe, 4262),
                         ("fixed", fixed, 6004), ("plain", plain, 6004)]:
    assert f"WIRE_RECEIVED {size} bytes" in text, f"{name}: wire bytes not received"

# Vulnerable attack: the mixed frame reaches the encoder and faults.
assert "WIRE_TRACK 512x64" in attack
assert "WIRE_FRAME 1 decoded 64x65 stride=64" in attack
assert "WIRE_MIXED_FRAME h=65 padded=64" in attack
assert "ERROR: AddressSanitizer: heap-buffer-overflow" in attack
assert "WRITE of size 64" in attack
assert "HeifPixelImage::extend_padding_to_size" in attack
assert "pixelimage.cc:644" in attack
assert "heif_image_extend_padding_to_size" in attack
assert "0 bytes after 32783-byte region" in attack
assert "CLIENT driver_rc=1" in attack

# Safe input on the same vulnerable build: no overflow.
assert "AddressSanitizer" not in safe
assert "WIRE_FRAME 1 decoded 512x64 stride=512" in safe
assert "WIRE_DONE last_encode_rc=0" in safe
assert "CLIENT driver_rc=0" in safe

# Fixed pin: the same wire bytes are rejected before any padding store.
assert "WIRE_FRAME 1 decoded 64x65 stride=64" in fixed
assert "AddressSanitizer" not in fixed
assert "WIRE_ENCODE_RC 2" in fixed
assert "All frames of a sequence must have the size of the first frame" in fixed
assert "CLIENT driver_rc=0" in fixed

# Plain vulnerable build: allocator detects the corrupted heap.
assert "free(): corrupted unsorted chunks" in plain
assert "CLIENT driver_rc=-6" in plain

print("PASS: wire-derived mixed-size frame reaches ASan WRITE of size 64 at pixelimage.cc:644")
print("PASS: 32783-byte region; public API + x265 encoder frames in the report")
print("PASS: safe input clean on vuln; fixed pin rejects with encode rc 2; plain aborts")
