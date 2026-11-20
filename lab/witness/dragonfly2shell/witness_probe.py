#!/usr/bin/env python3
"""Witness-only probe: key-length boundary for the DragonflyDB KeyEcho claim.

Same wire protocol as the committed trigger.py, looped over several lengths
against one container per build. Not part of the author's harness.
"""
import socket
import subprocess
import sys
import time

VER = sys.argv[1]
RESP = int(sys.argv[2])
MC = int(sys.argv[3])
LENS = [int(x) for x in sys.argv[4:]] or [250, 251, 8186, 8190, 8200, 20000, 32760]
NAME = "w11-witness-probe-" + VER.replace(".", "-")


def reply(sock, want_end=False):
    sock.settimeout(2)
    data = b""
    try:
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
            if want_end and data.endswith(b"END\r\n"):
                break
            if not want_end and data:
                break
    except (socket.timeout, ConnectionResetError):
        pass
    return data


subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)
subprocess.run(
    ["docker", "run", "-d", "--name", NAME,
     "-p", f"127.0.0.1:{RESP}:6379", "-p", f"127.0.0.1:{MC}:11211",
     "--entrypoint", "/usr/local/bin/dragonfly",
     f"ghcr.io/dragonflydb/dragonfly:{VER}",
     "--port", "6379", "--memcached_port", "11211"],
    check=True, capture_output=True,
)
try:
    for _ in range(100):
        try:
            s = socket.create_connection(("127.0.0.1", RESP), 0.3)
            s.close()
            break
        except OSError:
            time.sleep(0.2)
    time.sleep(2)

    print(f"build={VER}")
    for n in LENS:
        key = b"k" * n
        s = socket.create_connection(("127.0.0.1", RESP), 3)
        s.sendall(b"*3\r\n$3\r\nSET\r\n$" + str(n).encode() + b"\r\n" + key +
                  b"\r\n$5\r\nvalue\r\n")
        set_reply = reply(s)
        s.close()
        m = socket.create_connection(("127.0.0.1", MC), 3)
        m.sendall(b"get " + key + b"\r\n")
        out = reply(m, want_end=True)
        m.close()
        c = socket.create_connection(("127.0.0.1", MC), 2)
        c.sendall(b"get probe\r\n")
        alive = c.recv(200)
        c.close()
        print(f"  len={n:6d} set={set_reply!r} reply_wire_len={len(out):6d} "
              f"key_echoed={key in out} value_line={out.startswith(b'VALUE ')} "
              f"head={out[:40]!r} tail={out[-24:]!r} alive={alive!r}", flush=True)
finally:
    subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)
