import socket
import sys

path, port = sys.argv[1], int(sys.argv[2])
data = open(path, "rb").read()
s = socket.create_connection(("127.0.0.1", port), timeout=10)
s.sendall(data)
s.shutdown(socket.SHUT_WR)
s.close()
print("SENT bytes=%d" % len(data))
