#!/usr/bin/env python3
"""W184: check the ~1.2 kB mixed-size MJPEG reproducer's files and saved logs.

Usage: check_tiny_mjpeg.py EVIDENCE_DIR
No rebuild: verifies committed evidence only. Author observation, not witness
acceptance. The advisory's unpublished 1,155-byte PoC is NOT claimed matched;
the two mixed files here are 1,195 and 1,227 bytes.
"""
import hashlib
import sys
from pathlib import Path

HASHES = {
    "uniform64.jpg": "4f0396f825c0ff492161c03509d2d184e742b48bd5720534dfbf8772cd7492dc",
    "uniform72.jpg": "a77f60988fd3338bba97c0fac06c4d0f96aba3a1ff67d12b3f90130f94f6601e",
    "template.heif": "7d820881957402b629d0d627bee786566a1e0c7d13c455864807abad9492b9bc",
    "tiny64-ref.heif": "f2cb1ac007388ba234096ce22bbd8301fe98f6256616e1e338e51867461f2fcb",
    "tiny64-mixed.heif": "aa8e0600ada35537dd2f49314743571221719faaed3236371f10d031767e0c58",
    "tiny72-ref.heif": "a02b50a6094524b0f67e0639e473627c2d557fa6d7923054241c0ac1888d03c0",
    "tiny72-mixed.heif": "231bb209c008cd14e9d623c9a44975f7d3d7b171b847ca7a427da41ef1b94e89",
}
SIZES = {"tiny64-ref.heif": 1195, "tiny64-mixed.heif": 1195,
         "tiny72-ref.heif": 1227, "tiny72-mixed.heif": 1227}
RCS = {"asan64-mixed": 1, "asan72-mixed": 1,
       "asan64-safe": 0, "asan72-safe": 0,
       "plain64-mixed": 139, "plain72-mixed": 134,
       "fixed64-mixed": 0, "fixed72-mixed": 0}
PASS = []


def check(label, condition):
    PASS.append((label, bool(condition)))


def main():
    e = Path(sys.argv[1])
    for name, want in HASHES.items():
        p = e / name
        check(f"exists:{name}", p.exists())
        if p.exists():
            check(f"sha256:{name}", hashlib.sha256(p.read_bytes()).hexdigest() == want)
    for name, want in SIZES.items():
        p = e / name
        check(f"size:{name}={want}", p.exists() and p.stat().st_size == want)
    for name, want in RCS.items():
        p = e / f"{name}.rc"
        check(f"exists:{name}.rc", p.exists())
        if p.exists():
            check(f"rc:{name}={want}", p.read_text().strip() == str(want))

    logs = {}
    for name in RCS:
        p = e / f"{name}.out"
        check(f"exists:{name}.out", p.exists())
        logs[name] = p.read_text() if p.exists() else ""

    for name, region, frame0 in (
            ("asan64-mixed", "32783-byte region",
             "frame 0 decoded: 512x64 stride=512"),
            ("asan72-mixed", "36879-byte region",
             "frame 0 decoded: 512x72 stride=512")):
        log = logs[name]
        check(f"{name}:frame0", frame0 in log)
        check(f"{name}:frame1", "frame 1 decoded: 64x512 stride=64" in log)
        check(f"{name}:write64", "WRITE of size 64" in log)
        check(f"{name}:exact-region", f"0 bytes after {region}" in log)
        check(f"{name}:pinned-store", "pixelimage.cc:644" in log)
        check(f"{name}:public-api", "heif_image.cc:403" in log)
        check(f"{name}:x265-caller", "encoder_x265.cc:1139" in log)

    for name in ("asan64-safe", "asan72-safe"):
        log = logs[name]
        check(f"{name}:both-encoded", log.count("frame 1 encoded") == 1)
        check(f"{name}:no-asan", "AddressSanitizer" not in log)
    check("plain64:no-encode", "frame 1 encoded" not in logs["plain64-mixed"])
    check("plain72:abort-message",
          "double free or corruption (out)" in logs["plain72-mixed"])
    check("plain72:no-encode", "frame 1 encoded" not in logs["plain72-mixed"])

    for name in ("fixed64-mixed", "fixed72-mixed"):
        log = logs[name]
        check(f"{name}:decoded-mismatch", "frame 1 decoded: 64x512 stride=64" in log)
        check(f"{name}:encode-rc2", "encode: rc=2" in log)
        check(f"{name}:size-guard", "must have the size of the first frame" in log)
        check(f"{name}:no-asan", "AddressSanitizer" not in log)

    failed = [label for label, ok in PASS if not ok]
    print(f"PASS={len(PASS) - len(failed)} FAIL={len(failed)}")
    for label in failed:
        print(f"FAIL: {label}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
