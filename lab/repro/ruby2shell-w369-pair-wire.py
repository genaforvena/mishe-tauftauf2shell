#!/usr/bin/env python3
"""W369: ONE loopback request carrying two independent odd sharp-s operands.

Every plausible stock request surface is populated in the same request:
two ISO-8859-1 multipart values (21 and 23 0xDF), an ISO-8859-1 _method,
binary X-HTTP-Method-Override / Accept-Language / Content-Type parameter
names, and an ASCII query. Observational only: no custom middleware, no
debugger, no off-loopback traffic. Host stays ASCII so the stock Host
authorization middleware cannot short-circuit before multipart parsing.
"""

import socket
import sys

HOST = "127.0.0.1"
BOUNDARY = b"XW369BOUND"


def part(name, payload, charset=b"ISO-8859-1"):
    return (
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="' + name + b'"\r\n'
        b"Content-Type: text/plain; charset=" + charset + b"\r\n\r\n"
        + payload + b"\r\n"
    )


def main():
    port = int(sys.argv[1])
    method = sys.argv[2] if len(sys.argv) > 2 else "GET"
    left = b"a" + b"\xdf" * 21
    right = b"a" + b"\xdf" * 23
    body = b"".join([
        part(b"left", left),
        part(b"right", right),
        part(b"_method", left),
    ]) + b"--" + BOUNDARY + b"--\r\n"
    query = "/?left=one&right=two"
    headers = (
        b"Host: 127.0.0.1\r\n"
        b"X-HTTP-Method-Override: " + b"\xdf" * 23 + b"\r\n"
        b"Accept-Language: " + b"\xdf" * 21 + b"\r\n"
        b"Content-Type: multipart/form-data; boundary=" + BOUNDARY +
        b"; " + b"\xdf" * 21 + b"=v\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n"
    )
    request = method.encode() + b" " + query.encode() + b" HTTP/1.1\r\n" + headers + b"\r\n" + body
    try:
        with socket.create_connection((HOST, port), timeout=10) as sock:
            sock.sendall(request)
            chunks = []
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
        response = b"".join(chunks)
        head = response.split(b"\r\n", 1)[0].decode("latin-1")
    except Exception as exc:
        head = "ERR %s" % type(exc).__name__
    print("one-request-head=%s" % head)
    if " 400 " in head and "response" in locals():
        body_start = response.split(b"\r\n\r\n", 1)[-1]
        print("400-body-excerpt=%s" % body_start[:300].decode("latin-1", "replace").replace("\n", " "))


if __name__ == "__main__":
    main()
