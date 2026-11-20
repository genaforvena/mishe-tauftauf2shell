#!/usr/bin/env python3
"""Does 2.4.70 accept Huffman-coded HPACK values containing forbidden bytes?

Loopback only. Starts a private 2.4.70 instance, sends one h2c request per
case, reports the stream result, then terminates its own httpd tree. The
encoder is deliberately minimal: byte codewords are from RFC 7541 Appendix B
and cover only the bytes used below, so the script needs no third-party HPACK
library. Compare with alphabet-probe.py, which tests literal strings.

Observed 2026-11-20 18:25Z: literal 0x00 -> RST:1; Huffman-coded 0x00 -> RST:1
as well. Huffman does not smuggle a decoded NUL past nghttp2's field-value
validation, so the Stage C wire-alphabet boundary is not an artifact of
literal-only encoding.
"""
import os
import signal
import struct
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BASE = REPO / "lab/frontier/apache2root"
PREFIX = BASE / "install-2.4.70-asan"
sys.path.insert(0, str(HERE))
from h2client import (H2Connection, FRAME_HEADERS, FLAG_END_HEADERS,
                      FLAG_END_STREAM, _hpack_int)

# RFC 7541 Appendix B codewords for the bytes this probe emits.
HUFF = {
    0x00: (0x1FF8, 13), 0x09: (0xFFFFEA, 24), 0x0A: (0x3FFFFFFC, 30),
    0x0D: (0x3FFFFFFD, 30), 0x1F: (0xFFFFFFB, 28), 0x7F: (0xFFFFFFC, 28),
    0x41: (0x21, 6), 0x42: (0x5D, 7), 0x43: (0x5E, 7), 0x44: (0x5F, 7),
    0xFF: (0x3FFFFEE, 26),
}

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7220
CONF = HERE / "run" / ("huffman-probe-%d.conf" % PORT)
PIDFILE = HERE / "run" / ("huffman-probe-%d.pid" % PORT)
MODS = ("authn_core authz_core authz_host unixd mime log_config logio headers "
        "dir alias reqtimeout setenvif filter http2 cgi version")


def huffman_encode(raw):
    bits = 0
    nbits = 0
    out = bytearray()
    for byte in raw:
        code, length = HUFF[byte]
        bits = (bits << length) | (code & ((1 << length) - 1))
        nbits += length
        while nbits >= 8:
            nbits -= 8
            out.append((bits >> nbits) & 0xFF)
    if nbits:
        out.append(((bits << (8 - nbits)) | ((1 << (8 - nbits)) - 1)) & 0xFF)
    return bytes(out)


def hpack_string(raw, huffman):
    if not huffman:
        return _hpack_int(len(raw)) + raw
    wire = huffman_encode(raw)
    n = len(wire)
    if n < 127:
        return bytes([0x80 | n]) + wire
    out = bytearray([0xFF])
    n -= 127
    while n >= 128:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out) + wire


def header_block(value, huffman):
    fields = [(":method", "GET"), (":scheme", "http"),
              (":authority", "localhost"), (":path", "/index.html"),
              ("x-probe", value)]
    out = bytearray()
    for name, val in fields:
        if isinstance(name, str):
            name = name.encode()
        if isinstance(val, str):
            val = val.encode()
        use_huffman = huffman and name == b"x-probe"
        val_str = hpack_string(val, use_huffman)
        if use_huffman:
            assert val_str[0] & 0x80, "Huffman bit missing from value string"
        out += b"\x00" + hpack_string(name, False) + val_str
    return bytes(out)


def start_server():
    CONF.parent.mkdir(parents=True, exist_ok=True)
    with CONF.open("w") as f:
        f.write('ServerRoot "%s"\nPidFile "%s"\nListen 127.0.0.1:%d\n'
                % (PREFIX, PIDFILE, PORT))
        for m in MODS.split():
            f.write("LoadModule %s_module modules/mod_%s.so\n" % (m, m))
        f.write('ServerName localhost\nLogLevel info\n'
                'ErrorLog "%s"\nLogFormat "%%h %%l %%u %%t \\"%%r\\" %%>s %%b" common\n'
                'CustomLog "%s" common\n'
                'Protocols h2c http/1.1\nH2Direct on\n'
                'StartServers 1\nServerLimit 1\nThreadsPerChild 64\n'
                'DocumentRoot "%s"\n<Directory "%s">\n    Require all granted\n</Directory>\n'
                % (HERE / "run" / ("huffman-probe-%d.error.log" % PORT),
                   HERE / "run" / ("huffman-probe-%d.access.log" % PORT),
                   BASE / "htdocs", BASE / "htdocs"))
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=0:handle_segv=0"
    return subprocess.Popen([str(PREFIX / "bin/httpd"), "-f", str(CONF),
                             "-DFOREGROUND"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env=env)


def stop_server(proc):
    try:
        pid = int(PIDFILE.read_text().strip())
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (FileNotFoundError, ValueError, ProcessLookupError):
        proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def probe(value, huffman):
    conn = H2Connection("127.0.0.1", PORT, timeout=3.0)
    try:
        conn.handshake()
        conn.send_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM,
                        1, header_block(value, huffman))
        kind, payload = conn.read_until_response(1)
        if kind == "headers":
            return "200" if b"\x88" in payload else "headers:" + payload.hex()
        if kind == "rst":
            return "RST:%d" % struct.unpack(">I", payload[:4])[0]
        if kind == "goaway":
            return "GOAWAY:%d" % struct.unpack(">I", payload[4:8])[0]
        return kind
    except Exception as exc:
        return "%s:%s" % (type(exc).__name__, str(exc)[:60])
    finally:
        conn.close()


def self_check():
    """Fail before any traffic if Huffman coding is not on the value wire."""
    assert huffman_encode(b"\x00") == bytes.fromhex("ffc7")
    assert huffman_encode(b"ABCD") == bytes.fromhex("86edebff")
    assert huffman_encode(b"\x00\x00\x7f\xffABCD") == bytes.fromhex(
        "ffc7fe3ffffff3ffffee86edebff")
    for value in (b"A\x00B", b"\x00", b"\x00\x00\x7f\xffABCD",
                  b"\x0a", b"\x0d", b"\x7f", b"ABCD"):
        wire = huffman_encode(value)
        assert len(wire) < 127
        assert header_block(value, False).endswith(bytes([len(value)]) + value)
        assert header_block(value, True).endswith(
            bytes([0x80 | len(wire)]) + wire)


def main():
    self_check()
    proc = start_server()
    try:
        for _ in range(100):
            try:
                c = H2Connection("127.0.0.1", PORT, timeout=2.0)
                c.handshake()
                c.close()
                break
            except Exception:
                time.sleep(0.05)
        else:
            raise SystemExit("server did not start; see %s" % CONF)
        print("case                 value        result (2.4.70, h2c, 1 request/conn)")
        cases = [
            ("literal NUL", b"A\x00B", False),
            ("Huffman NUL", b"A\x00B", True),
            ("Huffman NUL only", b"\x00", True),
            ("Huffman ptr prefix", bytes.fromhex("00007fff") + b"ABCD", True),
            ("Huffman LF", b"\x0a", True),
            ("Huffman CR", b"\x0d", True),
            ("Huffman DEL", b"\x7f", True),
            ("Huffman ASCII control", b"ABCD", True),
        ]
        for label, value, huff in cases:
            print("%-20s %-12s %s" % (label, value.hex() + ("/H" if huff else "/L"),
                                      probe(value, huff)), flush=True)
    finally:
        stop_server(proc)


if __name__ == "__main__":
    main()
