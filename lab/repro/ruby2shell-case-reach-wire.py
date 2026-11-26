#!/usr/bin/env python3
"""Loopback-only wire arms for the String case-conversion reachability survey.

Sends single-byte-encoded 0xDF, UTF-8 sharp-s and an ASCII canary through every
stock request surface that can produce a String: Rack::MethodOverride `_method`,
other multipart params and filenames, override/host/accept headers, query values
and the Rails dev route grep. Observational only: no exploit payload, no
sanitizer bypass, no off-loopback traffic.
"""

import socket
import sys

HOST = "127.0.0.1"
BOUNDARY = b"XCASEBOUND"


def request(port, path="/not-a-route", extra=b"", body=b"", method=b"GET"):
    headers = b"Host: 127.0.0.1\r\nConnection: close\r\n"
    if body:
        headers += b"Content-Length: %d\r\n" % len(body)
    req = method + b" " + path.encode("latin-1") + b" HTTP/1.1\r\n" + headers + extra + b"\r\n" + body
    try:
        with socket.create_connection((HOST, port), timeout=5) as sock:
            sock.sendall(req)
            chunks = []
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
        head = b"".join(chunks).split(b"\r\n", 1)[0].decode("latin-1")
    except Exception as exc:
        head = "ERR %s" % type(exc).__name__
    return head


def multipart(name, payload, charset=b"ISO-8859-1", filename=None, field_ctype=None):
    disp = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        disp += b'; filename*=' + filename
    ctype = field_ctype if field_ctype is not None else b"text/plain; charset=" + charset
    part = (b"--" + BOUNDARY + b"\r\n" + disp + b"\r\nContent-Type: " + ctype +
            b"\r\n\r\n" + payload + b"\r\n")
    return part + b"--" + BOUNDARY + b"--\r\n"


def main():
    port = int(sys.argv[1])
    mode = sys.argv[2] if len(sys.argv) > 2 else "all"
    form = (b"Content-Type: multipart/form-data; boundary=" + BOUNDARY + b"\r\n")
    arms = []

    if mode in ("all", "control"):
        arms.append(("control-method-canary", request(port, extra=form, method=b"POST",
                                                      body=multipart(b"_method", b"CASECANARY123"))))
    if mode in ("all", "method"):
        arms.append(("method-iso-df", request(port, extra=form, method=b"POST",
                                              body=multipart(b"_method", b"\xdf"))))
        arms.append(("method-utf8-sharps", request(port, extra=form, method=b"POST",
                                                   body=multipart(b"_method", "ß".encode("utf-8"),
                                                                  charset=b"UTF-8"))))
        arms.append(("method-iso-canary", request(port, extra=form, method=b"POST",
                                                  body=multipart(b"_method", b"X2SHELLMETH"))))
    if mode in ("all", "fields"):
        arms.append(("q-iso-df", request(port, extra=form, method=b"POST",
                                          body=multipart(b"q", b"\xdf"))))
        arms.append(("q-utf8-sharps", request(port, extra=form, method=b"POST",
                                              body=multipart(b"q", "ß".encode("utf-8"),
                                                             charset=b"UTF-8"))))
        arms.append(("filename-iso-df", request(port, extra=form, method=b"POST",
                                                 body=multipart(b"file", b"x",
                                                                filename=b"ISO-8859-1''%DF.txt"))))
    if mode in ("all", "headers"):
        arms.append(("override-header-df", request(port, extra=b"X-HTTP-Method-Override: \xdf\r\n",
                                                   method=b"POST")))
        arms.append(("host-header-df", request(port, extra=b"Host: foo\xdf.example\r\n")))
        arms.append(("accept-language-df", request(port, extra=b"Accept-Language: \xdf\r\n")))
        arms.append(("content-type-df", request(port, extra=b"Content-Type: text/\xdf/plain\r\n",
                                                method=b"POST")))
    if mode in ("all", "query"):
        arms.append(("query-df", request(port, path="/not-a-route?q=%DF")))
        arms.append(("query-sharps", request(port, path="/not-a-route?q=%C3%9F")))
        arms.append(("routes-grep-df", request(port, path="/rails/info/routes?grep=%DF")))

    for name, status in arms:
        print(f"{name}={status}")


if __name__ == "__main__":
    main()
