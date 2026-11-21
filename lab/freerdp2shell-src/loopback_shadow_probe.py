#!/usr/bin/env python3
"""Loopback-only RDP transport / auth-gate probe for FreeRDP shadow server.

Exercises a live, source-built freerdp-shadow-cli bound to 127.0.0.1. It does
NOT touch the rdpsnd channel: its purpose is to move network reachability and
the NLA auth gate from UNKNOWN to observed for the FreeRDP server process.

Modes:
  nego      send an X.224 Connection Request with RDP_NEG_REQ and print the
            Connection Confirm / RDP_NEG_RSP for each security protocol.
  tls-auth  negotiate HYBRID (NLA), complete the TLS handshake, then withhold
            CredSSP credentials. The server must reject the session before
            MCS/channel setup; its log shows "client authentication failure".

Host is forced to 127.0.0.1: no off-loopback probing.
"""

import argparse
import binascii
import socket
import ssl
import struct
import sys

LOOPBACK = "127.0.0.1"


def connection_request(requested_protocols: int, cookie: str = "frprobe") -> bytes:
    """X.224 CR + RDP_NEG_REQ, built to match FreeRDP nego.c:1212-1226."""
    variable = b"Cookie: mstshash=" + cookie.encode() + b"\r\n"
    variable += struct.pack("<BBHI", 0x01, 0x00, 8, requested_protocols)
    # X224_TPDU_CONNECTION_REQUEST: code, DST-REF, SRC-REF, Class 0 (tpdu.c:117-137).
    body = bytes([0xE0, 0x00, 0x00, 0x00, 0x00, 0x00]) + variable
    # TPKT length = 4 header + 1 LI + body; LI = bytes after the LI (tpdu.c:123).
    return bytes([0x03, 0x00]) + struct.pack(">H", 5 + len(body)) + bytes([len(body)]) + body


def negotiate(port: int, timeout: float) -> None:
    for name, protocols in (
        ("HYBRID|HYBRID_EX (NLA)", 0x0000000A),
        ("TLS", 0x00000002),
        ("RDP", 0x00000000),
    ):
        try:
            s = socket.create_connection((LOOPBACK, port), timeout=timeout)
            s.settimeout(timeout)
            req = connection_request(protocols)
            s.sendall(req)
            data = s.recv(4096)
            print(f"{name}: TCP connect OK, CR {len(req)} bytes")
            print(f"  CR   = {binascii.hexlify(req).decode()}")
            print(f"  CC   = {binascii.hexlify(data).decode()} ({len(data)} bytes)")
            s.close()
        except OSError as exc:
            print(f"{name}: {type(exc).__name__}: {exc}")


def tls_auth(port: int, timeout: float) -> None:
    s = socket.create_connection((LOOPBACK, port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(connection_request(0x0000000A))
    cc = s.recv(4096)
    print(f"NLA negotiation CC = {binascii.hexlify(cc).decode()}")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        tls = context.wrap_socket(s, server_hostname="localhost")
        print(
            "TLS handshake: OK; cipher="
            + tls.cipher()[0]
            + "; peer cert present="
            + str(tls.getpeercert() is not None)
        )
        tls.settimeout(timeout)
        try:
            data = tls.recv(4096)
            print(
                f"post-TLS recv ({len(data)} bytes): "
                f"{binascii.hexlify(data[:64]).decode()}"
            )
        except socket.timeout:
            print("post-TLS: no bytes within timeout (server awaiting CredSSP/NLA token)")
        tls.close()
    except (ssl.SSLError, OSError) as exc:
        print(f"TLS/NLA EXC {type(exc).__name__}: {exc}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=13890)
    ap.add_argument("--mode", choices=("nego", "tls-auth"), default="nego")
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()
    print(f"target={LOOPBACK}:{args.port} mode={args.mode}")
    if args.mode == "nego":
        negotiate(args.port, args.timeout)
    else:
        tls_auth(args.port, args.timeout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
