#!/usr/bin/env python3
"""Minimal loopback-only FastCGI client used by the php2shell FPM lane harness.

Speaks just enough of the FastCGI 1.0 record protocol (BEGIN_REQUEST, PARAMS,
STDIN, STDOUT, STDERR, END_REQUEST) to drive a local php-fpm listener. No
external tooling (nginx, cgi-fcgi) is needed. All requests go to 127.0.0.1.

CLI:
    php2shell-fpm-client.py PORT SCRIPT_FILENAME [--param K=V ...] [--body FILE]
Prints the concatenated STDOUT then STDERR to stdout and exits 0 on a normal
END_REQUEST, 2 on protocol error/timeout.
"""

import socket
import struct
import sys

VERSION = 1
BEGIN_REQUEST = 1
END_REQUEST = 3
PARAMS = 4
STDIN = 5
STDOUT = 6
STDERR = 7
ROLE_RESPONDER = 1


def record(rtype, req_id, content=b""):
    pad = (-len(content)) % 8
    return (
        struct.pack("!BBHHBB", VERSION, rtype, req_id,
                    len(content), pad, 0)
        + content + (b"\0" * pad)
    )


def nvpair(name, value):
    n = name.encode() if isinstance(name, str) else name
    v = value.encode() if isinstance(value, str) else value
    def enc(x):
        if len(x) < 128:
            return bytes([len(x)])
        return struct.pack("!I", len(x) | 0x80000000)
    return enc(n) + enc(v) + n + v


def read_exact(sock, n):
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise EOFError("connection closed")
        out += chunk
    return out


def read_record(sock):
    h = read_exact(sock, 8)
    ver, rtype, rid, clen, plen, _ = struct.unpack("!BBHHBB", h)
    if ver != VERSION:
        raise ValueError("bad FastCGI version %d" % ver)
    content = read_exact(sock, clen)
    if plen:
        read_exact(sock, plen)
    return rtype, rid, content


def request(port, params, body=b"", req_id=1, timeout=25):
    """Return (stdout_bytes, stderr_bytes, app_status, protocol_status)."""
    out, err = b"", b""
    with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(record(BEGIN_REQUEST, req_id,
                         struct.pack("!HB5x", ROLE_RESPONDER, 0)))
        p = b"".join(nvpair(k, v) for k, v in params.items())
        for i in range(0, len(p), 65528):
            s.sendall(record(PARAMS, req_id, p[i:i + 65528]))
        s.sendall(record(PARAMS, req_id))
        for i in range(0, len(body), 65528):
            s.sendall(record(STDIN, req_id, body[i:i + 65528]))
        s.sendall(record(STDIN, req_id))
        while True:
            rtype, rid, content = read_record(s)
            if rid != req_id:
                continue
            if rtype == STDOUT:
                out += content
            elif rtype == STDERR:
                err += content
            elif rtype == END_REQUEST:
                app_status, proto = struct.unpack("!IB3x", content[:8])
                return out, err, app_status, proto
    raise EOFError("no END_REQUEST")


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    port, script = argv[1], argv[2]
    params = {
        "SCRIPT_FILENAME": script,
        "SCRIPT_NAME": "/" + script.rsplit("/", 1)[-1],
        "DOCUMENT_ROOT": script.rsplit("/", 1)[0],
        "REQUEST_METHOD": "GET",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "GATEWAY_INTERFACE": "CGI/1.1",
        "REDIRECT_STATUS": "200",
        "REMOTE_ADDR": "127.0.0.1",
    }
    body = b""
    i = 3
    while i < len(argv):
        if argv[i] == "--param" and i + 1 < len(argv):
            k, _, v = argv[i + 1].partition("=")
            params[k] = v
            i += 2
        elif argv[i] == "--body" and i + 1 < len(argv):
            with open(argv[i + 1], "rb") as f:
                body = f.read()
            params["REQUEST_METHOD"] = "POST"
            params["CONTENT_LENGTH"] = str(len(body))
            i += 2
        else:
            print("unknown arg: " + argv[i], file=sys.stderr)
            return 2
    try:
        out, err, app, proto = request(port, params, body)
    except (OSError, ValueError, EOFError) as e:
        print("FASTCGI_ERROR: %s" % e, file=sys.stderr)
        return 2
    sys.stdout.buffer.write(out)
    if err:
        sys.stdout.buffer.write(b"--- STDERR ---\n" + err)
    return 0 if proto == 0 else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
