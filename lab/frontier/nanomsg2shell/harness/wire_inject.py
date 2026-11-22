import socket
import sys

n = int(sys.argv[1]) if len(sys.argv) > 1 else 600
ver = b"Q" * n
req = (
    b"GET / HTTP/1.1\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"Host: localhost\r\n"
    b"Origin: http://localhost\r\n"
    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    b"Sec-WebSocket-Version: " + ver + b"\r\n"
    b"\r\n"
)
s = socket.create_connection(("127.0.0.1", 28765), timeout=5)
s.sendall(req)
s.settimeout(3)
try:
    data = s.recv(4096)
    print("reply_len=%d reply_head=%r" % (len(data), data[:80]))
except Exception as e:
    print("recv: %s" % e)
s.close()
