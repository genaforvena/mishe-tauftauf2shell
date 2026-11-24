#!/usr/bin/env python3
"""W183: check the genuine-512x72 reproducer's files, hashes and saved logs.

Usage: check_genuine_72.py EVIDENCE_DIR
No rebuild: verifies committed evidence only. PASS/FAIL are printed and the
exit status is nonzero when any assertion fails.
"""
import hashlib
import sys
from pathlib import Path

HASHES = {
    "f0.jpg": "652723cd946477e810afb4c1b60d6cac05d6e65c25c3e6a95c6377506675969a",
    "f1.jpg": "652723cd946477e810afb4c1b60d6cac05d6e65c25c3e6a95c6377506675969a",
    "ref.heif": "24c5906bd508988d3eafa3af73c4f86e0fa4157bb4a89d1bb1dd7e32e07da80e",
    "mixed.heif": "5a39f4885b8ae4d67754e96a983af5237e1af6acc51d8092efb073cbc0586a53",
}
RCS = {"asan-mixed": 1, "asan-ref": 0, "plain-mixed": 139,
       "plain-ref": 0, "fixed2-mixed": 0}
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
    for name, want in RCS.items():
        p = e / f"{name}.rc"
        check(f"exists:{name}.rc", p.exists())
        if p.exists():
            check(f"rc:{name}={want}", p.read_text().strip() == str(want))

    logs = {}
    for name in ("asan-mixed", "asan-ref", "plain-mixed", "plain-ref",
                 "fixed2-mixed", "gdb-mixed"):
        p = e / f"{name}.out"
        check(f"exists:{name}.out", p.exists())
        logs[name] = p.read_text() if p.exists() else ""

    safe = logs["asan-ref"]
    check("safe:track-512x72", "track declared: 512x72" in safe)
    check("safe:frame0-real", "frame 0 decoded: 512x72 stride=512" in safe)
    check("safe:frame1-512x72", "frame 1 decoded: 512x72 stride=512" in safe)
    check("safe:both-encoded", safe.count("encoded") >= 2)
    check("safe:no-asan", "AddressSanitizer" not in safe)
    check("plain-safe:no-warning", "Corrupt JPEG" not in logs["plain-ref"])

    attack = logs["asan-mixed"]
    check("attack:frame0-real", "frame 0 decoded: 512x72 stride=512" in attack)
    check("attack:frame1-64x512", "frame 1 decoded: 64x512 stride=64" in attack)
    check("attack:no-premature-frame0",
          "premature end of data" not in attack.split("frame 0 encoded")[0])
    check("attack:asan-write", "WRITE of size 64" in attack)
    check("attack:exact-region", "0 bytes after 36879-byte region" in attack)
    check("attack:pinned-store", "pixelimage.cc:644" in attack)
    check("attack:public-api", "heif_image.cc:403" in attack)
    check("attack:x265-caller", "encoder_x265.cc:1139" in attack)
    check("plain:segv-log", "SIGSEGV" in logs["gdb-mixed"])
    check("plain:memcpy-frame", "__memcpy_avx_unaligned_erms" in logs["gdb-mixed"])
    check("plain:padding-frame", "extend_padding_to_size" in logs["gdb-mixed"])

    fixed = logs["fixed2-mixed"]
    check("fixed:attack-decoded", "frame 1 decoded: 64x512 stride=64" in fixed)
    check("fixed:encode-rc2", "encode: rc=2" in fixed)
    check("fixed:size-guard", "must have the size of the first frame" in fixed)
    check("fixed:no-asan", "AddressSanitizer" not in fixed)

    failed = [label for label, ok in PASS if not ok]
    print(f"PASS={len(PASS) - len(failed)} FAIL={len(failed)}")
    for label in failed:
        print(f"FAIL: {label}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
