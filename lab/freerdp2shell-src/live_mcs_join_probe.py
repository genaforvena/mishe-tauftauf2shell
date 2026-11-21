#!/usr/bin/env python3
"""Minimal MCS + virtual-channel join probe against 127.0.0.1 shadow server.
Uses PyRDP protocol encoders from /tmp/fr-wake8-pyrdp (provisioned source).
RDP-only (no TLS/NLA) on a loopback peer; no off-loopback access.
"""
import binascii
import socket
import struct
import sys
import time

sys.path.insert(0, "/tmp/fr-wake8-pyrdp")
from pyrdp.enum import NegotiationProtocols, EncryptionMethod
from pyrdp.parser.mcs import MCSParser
from pyrdp.pdu.mcs import (MCSConnectInitialPDU, MCSDomainParams,
                           MCSErectDomainRequestPDU, MCSAttachUserRequestPDU,
                           MCSChannelJoinRequestPDU, MCSSendDataRequestPDU)
from pyrdp.parser.gcc import GCCParser
from pyrdp.pdu.gcc import GCCConferenceCreateRequestPDU
from pyrdp.parser.rdp.connection import ClientConnectionParser, ServerConnectionParser
from pyrdp.pdu.rdp.connection import ClientDataPDU

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 13891
HOST = "127.0.0.1"


def tpkt(payload: bytes) -> bytes:
    return bytes([3, 0]) + struct.pack(">H", 4 + len(payload)) + payload


def x224_data(mcs: bytes) -> bytes:
    return b"\x02\xf0\x80" + mcs  # LI, DT code, EOT (tpdu.c:126-129)


def recv_exact(s, n):
    out = b""
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk:
            raise EOFError("socket closed after %d of %d bytes" % (len(out), n))
        out += chunk
    return out


def recv_frame(s):
    h = recv_exact(s, 4)
    assert h[0] == 3, "not TPKT: %s" % h.hex()
    ln = struct.unpack(">H", h[2:4])[0]
    assert ln >= 7, "short TPKT %d" % ln
    body = recv_exact(s, ln - 4)
    if body[1] == 0xF0:  # X.224 DT: LI, 0xf0, EOT 0x80, then MCS
        return body[3:]
    return body[1:]  # X.224 CC: LI, 0xd0, then RDP_NEG_RSP


def cr_rdp():
    variable = b"Cookie: mstshash=frwake8\r\n" + struct.pack("<BBHI", 1, 0, 8, 0)
    body = bytes([0xE0, 0, 0, 0, 0, 0]) + variable
    return bytes([3, 0]) + struct.pack(">H", 5 + len(body)) + bytes([len(body)]) + body


def dump(tag, data):
    print("%s (%d): %s" % (tag, len(data), binascii.hexlify(data[:120]).decode()), flush=True)


def main():
    s = socket.create_connection((HOST, PORT), timeout=8)
    s.settimeout(8)
    s.sendall(cr_rdp())
    cc = recv_frame(s)
    dump("CC", cc)
    assert cc[0] == 0xD0, "no connection confirm"

    mcs_parser = MCSParser()
    client_data = ClientDataPDU.generate(
        NegotiationProtocols(0),
        encryptionMethods=EncryptionMethod.ENCRYPTION_128BIT,
        sound=True)
    gcc_bytes = GCCParser().write(
        GCCConferenceCreateRequestPDU("1", ClientConnectionParser().write(client_data)))
    ci = MCSConnectInitialPDU(b"\x01", b"\x01", True,
                              MCSDomainParams.createTarget(34, 2),
                              MCSDomainParams.createMinimum(),
                              MCSDomainParams.createMaximum(), gcc_bytes)
    s.sendall(tpkt(x224_data(mcs_parser.write(ci))))
    resp = recv_frame(s)
    dump("MCS CONNECT RESP", resp)
    cr = mcs_parser.parse(resp)
    print("connect result=%s payload_len=%d" % (cr.result, len(cr.payload)), flush=True)
    assert cr.result == 0, "MCS connect refused"
    gcc_resp = GCCParser().parse(cr.payload)
    server_data = ServerConnectionParser().parse(gcc_resp.payload)
    chan_ids = server_data.networkData.channels
    io_id = server_data.networkData.mcsChannelID
    print("server io channel=%d channels=%r" % (io_id, chan_ids), flush=True)

    s.sendall(tpkt(x224_data(mcs_parser.write(MCSErectDomainRequestPDU(0, 0, b"")))))
    # Attach user; server may batch responses.
    s.sendall(tpkt(x224_data(mcs_parser.write(MCSAttachUserRequestPDU()))))
    f = recv_frame(s)
    dump("ERECT/ATTACH frame", f)
    au = mcs_parser.parse(f)
    user_id = au.initiator
    print("attach user id=%d result=%s" % (user_id, au.result), flush=True)

    joins = [user_id, io_id] + list(chan_ids)
    for cid in joins:
        s.sendall(tpkt(x224_data(mcs_parser.write(MCSChannelJoinRequestPDU(user_id, cid, b"")))))
    for i in range(len(joins)):
        f = recv_frame(s)
        jc = mcs_parser.parse(f)
        print("join confirm requested=%s channelID=%s result=%s" %
              (jc.requested, jc.channelID, jc.result), flush=True)

    print("MCS/JOIN COMPLETE", flush=True)
    def audio(tag, ch, rate, avg, align, bits, ext=b""):
        return struct.pack("<HHIIHHH", tag, ch, rate, avg, align, bits, len(ext)) + ext

    def formats_pdu(fmt):
        body = struct.pack("<IIIHHBH", 0, 0xFFFFFFFF, 0, 0, 1, 1, 0) + fmt
        return struct.pack("<BBH", 7, 0, len(body)) + body

    def channel_payload(pdu):
        return struct.pack("<II", len(pdu), 0) + pdu  # totalSize, flags (channels.c:316-319)

    pcm = audio(1, 2, 44100, 176400, 4, 16)
    adpcm = audio(2, 2, 44100, 176400, 8, 16)
    for name, fmt in (("pcm", pcm), ("adpcm", adpcm)):
        payload = channel_payload(formats_pdu(fmt))
        s.sendall(tpkt(x224_data(mcs_parser.write(
            MCSSendDataRequestPDU(user_id, chan_ids[0], 0, payload)))))
        print("SENT %s SNDC_FORMATS (%d wire bytes)" % (name, len(payload)), flush=True)
        time.sleep(1)

    s.settimeout(2)
    try:
        while True:
            dump("SERVER FRAME", recv_frame(s))
    except Exception as e:
        print("drain end: %s" % type(e).__name__, flush=True)
    print("PDU SEND COMPLETE", flush=True)
    s.close()


if __name__ == "__main__":
    main()
