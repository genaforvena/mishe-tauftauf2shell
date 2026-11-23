#!/usr/bin/env python3
"""W181: assert the advisory-size single-file ASan observation and controls.

Usage: check_advisory_size.py EVIDENCE_DIR   (default: the committed evidence dir)
Checks author evidence only, not an independent replay. No rebuild is needed.
"""
import hashlib
import sys
from pathlib import Path

SHA = {
    "advisory.heif": "d749c1bd05264319a26449eeb73bccd771c0eb327524f27c658ac679f4ce79fe",
    "safe72.heif": "fe3b4d4da5ef0a762a78263dc03fbb7da8e77e2b40bb8abd6917ffa38e029419",
}


def main():
    here = Path(__file__).resolve().parent
    d = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "evidence/advisory-size"
    checks = []

    for name, digest in SHA.items():
        got = hashlib.sha256((d / name).read_bytes()).hexdigest()
        checks.append((f"{name} sha256", got == digest, got))

    def rc(name):
        return (d / name).read_text().strip()

    def out(name):
        return (d / name).read_text(errors="replace")

    atk = out("advisory.out")
    checks.append(("attack rc=1", rc("advisory.rc") == "1", rc("advisory.rc")))
    checks.append(("attack file frames 512x72 then 64x512",
                   "frame 0 decoded: 512x72 stride=512" in atk and
                   "frame 1 decoded: 64x512 stride=64" in atk, ""))
    checks.append(("attack ASan heap-buffer-overflow WRITE 64",
                   "heap-buffer-overflow" in atk and "WRITE of size 64" in atk, ""))
    checks.append(("attack 0 bytes after 36879-byte region",
                   "0 bytes after 36879-byte region" in atk, ""))
    checks.append(("attack pinned call chain", all(s in atk for s in (
        "pixelimage.cc:631", "pixelimage.cc:644", "heif_image.cc:403",
        "encoder_x265.cc:1139", "track_visual.cc:620")), ""))

    safe = out("safe72.out")
    checks.append(("safe rc=0", rc("safe72.rc") == "0", rc("safe72.rc")))
    checks.append(("safe no ASan, both frames encoded",
                   "AddressSanitizer" not in safe and
                   "frame 0 encoded" in safe and "frame 1 encoded" in safe and
                   "frame 1 decoded: 512x72 stride=512" in safe, ""))

    dec = out("decode.out")
    checks.append(("decode-only rc=0 and mixed sizes",
                   rc("decode.rc") == "0" and
                   "frame 0 decoded: 512x72 stride=512" in dec and
                   "frame 1 decoded: 64x512 stride=64" in dec, ""))

    fixed = out("fixed.out")
    checks.append(("fixed rc=0 with encode rejection",
                   rc("fixed.rc") == "0" and "encode: rc=2" in fixed and
                   "All frames of a sequence must have the size of the first frame" in fixed and
                   "AddressSanitizer" not in fixed, ""))

    for name, ok, detail in checks:
        print(f"{'PASS' if ok else 'FAIL'} {name}" + (f" {detail}" if detail and not ok else ""))
    fails = sum(1 for _, ok, _ in checks if not ok)
    print(f"PASS={len(checks)-fails} FAIL={fails}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
