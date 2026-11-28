#!/usr/bin/env python3
"""Safe-input arm: same two-step loopback exchange, hdr.length=100 (dlen=52).

52 bytes fit inside the 152-byte stack destination, so no overflow.  Uses the
unmodified peer.py wire/framing code, monkeypatching only ticket construction.
"""
import os
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import peer

peer.LENGTH = 100


def safe_ticket(mode, iv):
    plain = (b"FREERADIUS2SHELL-SAFE-INPUT-ARM-" * 3)[:52]
    cipher = AESGCM(peer.KEY).encrypt(iv, plain, peer.A_ID)[:52]
    return (struct.pack("!HH", 2, peer.LENGTH) + peer.A_ID + iv +
            b"\x00" * 16 + cipher)


peer.ticket = safe_ticket
sys.exit(peer.main())
