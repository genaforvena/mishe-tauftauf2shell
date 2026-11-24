#!/usr/bin/env python3
"""W187: single-image HEIF encode reaches the padding call with matched sizes.

Usage: check_single_image.py [GDB_LOG]  (default: committed evidence log)
Checks author evidence, not an independent replay. No rebuild or live run.
"""
import hashlib
import sys
from pathlib import Path

JPEG_SHA = "4f0396f825c0ff492161c03509d2d184e742b48bd5720534dfbf8772cd7492dc"


def main():
    here = Path(__file__).resolve().parent
    log_path = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "evidence/single-image-padding.gdb.out"
    log = log_path.read_text(errors="replace")
    jpeg = here / "evidence/tiny-mjpeg/uniform64.jpg"
    digest = hashlib.sha256(jpeg.read_bytes()).hexdigest()

    check = [
        ("input sha256", digest == JPEG_SHA, digest),
        ("padding reached", "hit Breakpoint 1, heif_image_extend_padding_to_size" in log, ""),
        ("request matches image 512x64", "min_physical_width=512, min_physical_height=64" in log, ""),
        ("called by sequence-frame plugin",
         "x265_encode_sequence_frame" in log and "encoder_x265.cc:1139" in log, ""),
        ("single-image x265_encode_image",
         "x265_encode_image" in log and "encoder_x265.cc:1252" in log, ""),
        ("public encode path", "Encoder_HEVC::encode" in log and "hevc_enc.cc:75" in log, ""),
        ("clean exit", "[Inferior 1" in log and "exited normally" in log, ""),
        ("no ASan report", "ERROR: AddressSanitizer" not in log, ""),
    ]

    for name, ok, detail in check:
        print(f"{'PASS' if ok else 'FAIL'} {name}" + (f" {detail}" if detail and not ok else ""))
    fails = sum(1 for _, ok, _ in check if not ok)
    print(f"PASS={len(check)-fails} FAIL={fails}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
