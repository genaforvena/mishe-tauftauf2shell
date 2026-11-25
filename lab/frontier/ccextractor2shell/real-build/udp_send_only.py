#!/usr/bin/env python3
"""W10 local-only sender: feed a crafted GXF to an already-running --udp listener.

The target binary is started separately (under GDB). Only 127.0.0.1 is used.
"""
import argparse
import pathlib
import socket
import struct
import time


def eos_packet() -> bytes:
    header = b"\x00\x00\x00\x00\x01\xfb" + struct.pack(">I", 32)
    return header + b"\x00\x00\x00\x00\xe1\xe2" + b"\x41" * 16


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=pathlib.Path)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--pace", type=float, default=0.004)
    args = ap.parse_args()
    data = args.input.read_bytes()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
    for offset in range(0, len(data), 8192):
        sock.sendto(data[offset:offset + 8192], ("127.0.0.1", args.port))
        time.sleep(args.pace)
    for _ in range(3):
        sock.sendto(eos_packet(), ("127.0.0.1", args.port))
        time.sleep(0.02)
    sock.close()
    print("sent input=%s bytes=%d datagrams=%d to 127.0.0.1:%d" %
          (args.input.name, len(data), (len(data) + 8191) // 8192, args.port))


if __name__ == "__main__":
    main()
