#!/usr/bin/env python3
"""Minimal VRPN TCP client: cookie exchange then one SENDER_DESCRIPTION message.

The payload's first big-endian int32 is the index the server uses for
`sender_name[i] = '\0'` in vrpn_Connection.C:4554 (v07.36). No external hosts.
"""
import argparse
import socket
import struct
import time

COOKIE_SIZE = 24  # vrpn_MAGICLEN(16) + vrpn_ALIGN(8)
HEADER_LEN = 24   # 5 int32 fields (20) rounded up to vrpn_ALIGN(8)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--port", type=int, default=3893)
    ap.add_argument("--hold", type=float, default=2.0)
    args = ap.parse_args()

    payload = struct.pack(">i", args.index) + args.name.encode()
    payload_len = len(payload)
    ceil_len = payload_len + (-payload_len % 8)
    msg = struct.pack(">IIIIII", HEADER_LEN + payload_len, 0, 0, 0, 0xFFFFFFFF, 0)
    msg += b"\0" * (HEADER_LEN - 20)
    msg += payload + b"\0" * (ceil_len - payload_len)

    with socket.create_connection(("127.0.0.1", args.port), timeout=5) as s:
        cookie = s.recv(COOKIE_SIZE)
        if len(cookie) != COOKIE_SIZE:
            raise SystemExit(f"short cookie: {cookie!r}")
        s.sendall(cookie)
        time.sleep(0.2)
        s.sendall(msg)
        time.sleep(args.hold)
        print(f"cookie={cookie!r}")
        print(f"index={args.index} payload_len={payload_len} msg_len={len(msg)}")


if __name__ == "__main__":
    main()
