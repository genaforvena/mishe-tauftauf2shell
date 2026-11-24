#!/usr/bin/env python3
"""Replay checks for the W189 ImageMagick consumer observation.

Usage: python3 check_im_consumer.py EVIDENCE_DIR
Checks committed bytes only; it does not rebuild ImageMagick or libheif.
"""
import hashlib
import pathlib
import sys

INPUT_SHA = "73590bbd702820ebebba3c9e490f694fdbd5cfdcc1281f6ca92958eed71f392d"


def main() -> int:
    d = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    results = []

    def check(name, ok, detail=""):
        results.append((name, bool(ok), detail))

    miff = d / "mixed-frames.miff"
    check("input sha256",
          miff.is_file() and hashlib.sha256(miff.read_bytes()).hexdigest() == INPUT_SHA,
          "")
    check("heic rc 0", (d / "heic-mixed.rc").read_text().strip() == "0", "")
    check("avif rc 0", (d / "avif-mixed.rc").read_text().strip() == "0", "")
    heic = (d / "heif-info-heic.out").read_text()
    check("heic two independent still images",
          "image: 512x64 (id=1), primary" in heic
          and "image: 64x65 (id=2)" in heic, "")
    avif = (d / "heif-info-avif.out").read_text()
    check("avif two mixed frames", "image: 512x64 (id=1), primary" in avif
          and "image: 64x65 (id=2)" in avif, "")
    dispatch = (d / "gdb-dispatch.out").read_text()
    check("sequence branch eligible",
          "DISPATCH magick=AVIF adjoin=1 next=" in dispatch, "")
    cfg = (d / "configure.log").read_text()
    check("delegate configured", "HEIC" in cfg and "--with-heic=yes" in cfg, "")

    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}: {name}" + (f" {detail}" if detail else ""))
    passed = sum(ok for _, ok, _ in results)
    print(f"SUMMARY pass={passed} fail={len(results) - passed}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
