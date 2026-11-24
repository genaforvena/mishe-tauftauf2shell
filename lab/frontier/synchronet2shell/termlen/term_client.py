#!/usr/bin/env python3
"""Loopback-only paramiko client for the W11 TERM-length residual probe.

Unlike the OpenSSH clients used in W8, this client records the exact pty-req
TERM string it hands to paramiko's transport encryption, so client-side
truncation can be excluded by measurement rather than by source reading.
paramiko's channel.py builds the request with m.add_string(term) and no cap.
The --pad-channel-open accommodation from W9 is not needed here: the W8 wire
server sets CRYPT_SSHOPTION_NONE_AUTH and accepts the RFC-shaped channel-open.
"""

import argparse
import socket
import sys
import time

import paramiko


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--term-length", type=int, required=True)
    ap.add_argument("--seconds", type=int, default=8)
    args = ap.parse_args()

    term = b"T" * args.term_length
    started = time.time()
    wire_terms = []

    def log(msg):
        print(f"{time.time() - started:6.2f} CLIENT {msg}", flush=True)

    sock = socket.create_connection(("127.0.0.1", args.port), timeout=8)
    t = paramiko.ServiceRequestingTransport(sock)
    t.start_client(timeout=10)
    log(f"kex done remote_version={t.remote_version!r}")
    t.ensure_session()
    log("service ssh-userauth accepted")
    t.auth_handler.send_auth_request("lab", "none", lambda m: None)
    log("auth_none accepted")

    original = t._send_user_message

    def record_ptyreq(msg):
        raw = msg.asbytes()
        if raw and raw[0] == 98:  # SSH_MSG_CHANNEL_REQUEST
            parsed = paramiko.Message(raw)
            try:
                parsed.get_byte()
                parsed.get_int()
                request = parsed.get_string()
                parsed.get_boolean()
                if request == b"pty-req":
                    wire_term = parsed.get_string()
                    wire_terms.append(wire_term)
                    log(f"WIRE_PTYREQ term_len={len(wire_term)} "
                        f"head={wire_term[:8]!r}")
            except Exception as exc:  # keep the negative observable
                log(f"WIRE_PTYREQ parse error {exc!r}")
        return original(msg)

    t._send_user_message = record_ptyreq
    try:
        ch = t.open_session(timeout=10)
        log(f"channel open chanid={ch.chanid}")
        ch.get_pty(term=term, width=80, height=24,
                   width_pixels=640, height_pixels=480)
        ch.invoke_shell()
        log("shell request sent")
        deadline = time.time() + args.seconds
        while time.time() < deadline:
            if ch.send_ready():
                ch.send("x\n")
            if ch.recv_ready():
                data = ch.recv(4096)
                log(f"recv {len(data)} bytes: {data[:80]!r}")
            time.sleep(0.2)
        log("done")
    except Exception as exc:
        log(f"channel error {exc!r}")
    finally:
        t.close()

    if len(wire_terms) != 1:
        log(f"FAIL expected one pty-req, saw {len(wire_terms)}")
        return 3
    if len(wire_terms[0]) != args.term_length:
        log(f"FAIL client truncated TERM: wanted {args.term_length}, "
            f"sent {len(wire_terms[0])}")
        return 4
    log(f"PASS exact wire TERM length {len(wire_terms[0])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
