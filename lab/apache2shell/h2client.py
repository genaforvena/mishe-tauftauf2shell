#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal HTTP/2 client (RFC 7540 / RFC 7541 subset), Python standard library only.

Only what a race-condition PoC needs:

  * connection preface + SETTINGS exchange,
  * HEADERS frames carrying a pseudo-header block encoded with HPACK
    "literal header field without indexing / new name" (never touches the
    dynamic table, so the encoder stays stateless),
  * DATA frames, CONTINUATION frames, WINDOW_UPDATE and PING,
  * a frame reader that returns raw frames.

Response header blocks are not decoded - the PoC only needs to know that a
response arrived, not what it says.
"""

import socket
import struct
import time

# ---------------------------------------------------------------- constants

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_PRIORITY = 0x2
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_PUSH_PROMISE = 0x5
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8
FRAME_CONTINUATION = 0x9

FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20

# The server may open as many streams as it wants; the PoC uses odd ids
# (client initiated streams must be odd) counted from 1.

DEFAULT_WINDOW = 65535


class ProtocolError(Exception):
    pass


class ConnectionClosed(Exception):
    pass


# ------------------------------------------------------------------ HPACK

def _hpack_int(value, prefix_bits=7):
    """HPACK integer with an N-bit prefix (RFC 7541 section 5.1)."""
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes([value])
    out = bytearray([limit])
    value -= limit
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _hpack_string(raw):
    """HPACK string literal, no Huffman coding."""
    return _hpack_int(len(raw)) + raw


def hpack_literal(name, value):
    """
    "Literal Header Field without Indexing - New Name" (RFC 7541 6.2.2).

    The 0x00 prefix means the field is never added to the dynamic table and
    never references it, which keeps the encoder completely stateless.  The
    receiver's decoder state therefore never diverges from ours.
    """
    if isinstance(name, str):
        name = name.encode("utf-8")
    if isinstance(value, str):
        value = value.encode("utf-8")
    return b"\x00" + _hpack_string(name) + _hpack_string(value)


def encode_headers(headers):
    """headers: list of (name, value) pairs, pseudo-headers first."""
    out = bytearray()
    for name, value in headers:
        out += hpack_literal(name, value)
    return bytes(out)


# ------------------------------------------------------------------ frames

def build_frame(frame_type, flags, stream_id, payload=b""):
    return (struct.pack(">I", len(payload))[1:]
            + bytes([frame_type & 0xFF, flags & 0xFF])
            + struct.pack(">I", stream_id & 0x7FFFFFFF)
            + payload)


def build_settings(settings=None):
    payload = b""
    for ident, value in (settings or {}).items():
        payload += struct.pack(">HI", ident, value)
    return build_frame(FRAME_SETTINGS, 0, 0, payload)


# ------------------------------------------------------------------ client

class H2Connection:
    """A single HTTP/2 connection speaking cleartext h2c."""

    def __init__(self, host, port, timeout=10.0, connect_timeout=5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._buf = b""
        self.sock = socket.create_connection((host, port), connect_timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(timeout)
        self.goaway = None
        self.settings_received = False

    # ------------------------------------------------------------ low level

    def _send(self, data):
        try:
            self.sock.sendall(data)
        except (BrokenPipeError, ConnectionResetError, OSError) as exc:
            raise ConnectionClosed(str(exc))

    def send_raw(self, data):
        self._send(data)

    def send_frame(self, frame_type, flags, stream_id, payload=b""):
        self._send(build_frame(frame_type, flags, stream_id, payload))

    def _recv_exact(self, n):
        while len(self._buf) < n:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                raise
            except OSError as exc:
                raise ConnectionClosed(str(exc))
            if not chunk:
                raise ConnectionClosed("peer closed the connection")
            self._buf += chunk
        data, self._buf = self._buf[:n], self._buf[n:]
        return data

    def read_frame(self):
        """Return (frame_type, flags, stream_id, payload)."""
        header = self._recv_exact(9)
        length = int.from_bytes(header[0:3], "big")
        frame_type = header[3]
        flags = header[4]
        stream_id = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
        payload = self._recv_exact(length) if length else b""
        return frame_type, flags, stream_id, payload

    # ------------------------------------------------------------ handshake

    def handshake(self, settings=None):
        """Send the preface, exchange SETTINGS, return the server SETTINGS."""
        self._send(PREFACE)
        self.send_frame(FRAME_SETTINGS, 0, 0, struct.pack(">HI", 0x3, 0x100)
                        if False else b"")
        if settings:
            self.send_frame(FRAME_SETTINGS, 0, 0, settings)
        # Read frames until the server's SETTINGS arrives, answering PING.
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            frame_type, flags, stream_id, payload = self.read_frame()
            if frame_type == FRAME_SETTINGS and not (flags & FLAG_ACK):
                self.settings_received = True
                self.send_frame(FRAME_SETTINGS, FLAG_ACK, 0)
                return payload
            if frame_type == FRAME_PING and not (flags & FLAG_ACK):
                self.send_frame(FRAME_PING, FLAG_ACK, 0, payload)
            if frame_type == FRAME_GOAWAY:
                self.goaway = payload
                raise ProtocolError("server sent GOAWAY during handshake")
        raise ProtocolError("timed out waiting for the server SETTINGS frame")

    # ------------------------------------------------------------ requests

    def send_request_headers(self, stream_id, headers, end_stream=True,
                             end_headers=True, extra_flags=0):
        block = encode_headers(headers)
        flags = extra_flags
        if end_headers:
            flags |= FLAG_END_HEADERS
        if end_stream:
            flags |= FLAG_END_STREAM
        if len(block) <= 16384:
            self.send_frame(FRAME_HEADERS, flags, stream_id, block)
            return
        # Split into HEADERS + CONTINUATION frames.
        first, rest = block[:16384], block[16384:]
        self.send_frame(FRAME_HEADERS, flags & ~FLAG_END_HEADERS, stream_id, first)
        while rest:
            chunk, rest = rest[:16384], rest[16384:]
            self.send_frame(FRAME_CONTINUATION,
                            FLAG_END_HEADERS if not rest else 0,
                            stream_id, chunk)

    def send_data(self, stream_id, data, end_stream=True):
        flags = FLAG_END_STREAM if end_stream else 0
        self.send_frame(FRAME_DATA, flags, stream_id, data)

    def send_continuation(self, stream_id, headers, end_headers=True):
        """Send a CONTINUATION frame carrying the tail of a header block."""
        block = encode_headers(headers)
        flags = FLAG_END_HEADERS if end_headers else 0
        self.send_frame(FRAME_CONTINUATION, flags, stream_id, block)

    def send_rst_stream(self, stream_id, error_code=8):
        self.send_frame(FRAME_RST_STREAM, 0, stream_id,
                        struct.pack(">I", error_code))

    def send_window_update(self, stream_id, increment):
        self.send_frame(FRAME_WINDOW_UPDATE, 0, stream_id,
                        struct.pack(">I", increment & 0x7FFFFFFF))

    # ------------------------------------------------------------ reading

    def read_until_response(self, stream_id, deadline=None):
        """
        Read frames until a response HEADERS/DATA frame arrives for stream_id.

        Returns a tuple (kind, payload) where kind is one of
        "headers", "data", "eor", "rst", "goaway", "timeout".
        """
        deadline = deadline or (time.time() + self.timeout)
        while time.time() < deadline:
            self.sock.settimeout(max(0.05, deadline - time.time()))
            try:
                frame_type, flags, sid, payload = self.read_frame()
            except socket.timeout:
                return "timeout", b""
            except ConnectionClosed:
                return "closed", b""
            if frame_type == FRAME_HEADERS and sid == stream_id:
                return "headers", payload
            if frame_type == FRAME_DATA and sid == stream_id:
                if flags & FLAG_END_STREAM:
                    return "eor", payload
                return "data", payload
            if frame_type == FRAME_RST_STREAM and sid == stream_id:
                return "rst", payload
            if frame_type == FRAME_GOAWAY:
                self.goaway = payload
                return "goaway", payload
            if frame_type == FRAME_PING and not (flags & FLAG_ACK):
                self.send_frame(FRAME_PING, FLAG_ACK, 0, payload)
        return "timeout", b""

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def default_headers(method="GET", scheme="http", authority="localhost",
                    path="/", extra=()):
    """A well-formed HTTP/2 request header block."""
    headers = [
        (":method", method),
        (":scheme", scheme),
        (":authority", authority),
        (":path", path),
    ]
    headers.extend(extra)
    return headers
