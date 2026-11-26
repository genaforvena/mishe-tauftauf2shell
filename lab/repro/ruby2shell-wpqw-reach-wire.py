#!/usr/bin/env python3
"""Loopback-only request generator for the wpqw wire-reachability survey.

Sends wide-encoded bytes through every stock request surface that can turn a
header/part into a Ruby String: Accept header, multipart part charset, query
string and (Rails dev) route-inspector grep. No exploit claim: this only asks
whether a default path compiles a wide-encoded Regexp pattern.
"""

import socket
import sys
import urllib.parse

HOST = "127.0.0.1"


def pattern(kind):
    text = "(?i:w)\u03ab"
    if kind == "u16":
        return text.encode("utf-16le")
    return text.encode("utf-32le")


def request(port, body=b"", path="/not-a-route", extra=b"", method=b"POST"):
    headers = b"Host: 127.0.0.1\r\nConnection: close\r\n"
    if body:
        headers += b"Content-Length: %d\r\n" % len(body)
    req = method + b" " + path.encode() + b" HTTP/1.1\r\n" + headers + extra + b"\r\n" + body
    with socket.create_connection((HOST, port), timeout=5) as sock:
        sock.sendall(req)
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    head = b"".join(chunks).split(b"\r\n", 1)[0].decode("latin-1")
    return head


def multipart(charset, payload):
    part = (
        b"--XB\r\nContent-Disposition: form-data; name=\"_method\"\r\n"
        b"Content-Type: text/plain; charset=" + charset + b"\r\n\r\n" + payload + b"\r\n"
    )
    tail = (
        b"--XB\r\nContent-Disposition: form-data; name=\"q\"\r\n"
        b"Content-Type: text/plain; charset=" + charset + b"\r\n\r\n"
        + "\u1e98\u03ab".encode("utf-16le" if charset == b"UTF-16LE" else "utf-32le")
        + b"\r\n--XB--\r\n"
    )
    return part + tail


def multipart_q_only(charset, payload):
    return (
        b"--XB\r\nContent-Disposition: form-data; name=\"q\"\r\n"
        b"Content-Type: text/plain; charset=" + charset + b"\r\n\r\n"
        + payload + b"\r\n--XB--\r\n"
    )


def main():
    port = int(sys.argv[1])
    kind = sys.argv[2] if len(sys.argv) > 2 else "all"
    arms = []
    if kind in ("all", "accept"):
        arms.append(("accept-u16", request(port, path="/not-a-route",
                                           extra=b"Accept: " + pattern("u16") + b"\r\n",
                                           method=b"GET")))
        arms.append(("accept-u32", request(port, path="/not-a-route",
                                           extra=b"Accept: " + pattern("u32") + b"\r\n",
                                           method=b"GET")))
    if kind in ("all", "part"):
        ctype = b"Content-Type: multipart/form-data; boundary=XB\r\n"
        arms.append(("part-u16", request(port, multipart(b"UTF-16LE", pattern("u16")),
                                         extra=ctype)))
        arms.append(("part-u32", request(port, multipart(b"UTF-32LE", pattern("u32")),
                                         extra=ctype)))
        arms.append(("part-u16-valid", request(port,
                                               multipart(b"UTF-16LE", "x".encode("utf-16le")),
                                               extra=ctype)))
        arms.append(("part-u32-valid", request(port,
                                               multipart(b"UTF-32LE", "x".encode("utf-32le")),
                                               extra=ctype)))
        arms.append(("q-u16-valid", request(port,
                                            multipart_q_only(b"UTF-16LE", "x".encode("utf-16le")),
                                            extra=ctype)))
        arms.append(("q-u16-shape", request(port,
                                            multipart_q_only(b"UTF-16LE",
                                                             "\u1e98\u03ab".encode("utf-16le")),
                                            extra=ctype)))
        arms.append(("q-u32-valid", request(port,
                                            multipart_q_only(b"UTF-32LE", "x".encode("utf-32le")),
                                            extra=ctype)))
    if kind in ("all", "query"):
        q = urllib.parse.quote_from_bytes(pattern("u16"))
        arms.append(("query-u16", request(port, path="/not-a-route?q=" + q,
                                          method=b"GET")))
    if kind in ("all", "grep"):
        q = urllib.parse.quote_from_bytes(pattern("u16"))
        arms.append(("routes-grep-u16", request(port,
                                                path="/rails/info/routes?grep=" + q,
                                                method=b"GET")))
    if kind in ("all", "canary"):
        canary = b"X2SHELLCANARY123"
        arms.append(("canary-header", request(port, path="/not-a-route",
                                              extra=b"X-Canary: " + canary + b"\r\n"
                                                    b"Accept: text/html\r\n", method=b"GET")))
        arms.append(("canary-query", request(port, path="/not-a-route?q=" + canary.decode(),
                                             method=b"GET")))
        ctype = b"Content-Type: multipart/form-data; boundary=XB\r\n"
        arms.append(("canary-body", request(port, multipart_q_only(b"UTF-8", canary),
                                            extra=ctype)))
        arms.append(("canary-agent", request(port, path="/not-a-route",
                                             extra=b"User-Agent: " + canary + b"\r\n", method=b"GET")))
    for name, status in arms:
        print(f"{name}={status}")


if __name__ == "__main__":
    main()
