#!/usr/bin/env python3
"""W182: assert plain/ASan/fixed fault modes on the advisory-size input family.

Usage: check_plain_fault_modes.py EVIDENCE_DIR
Checks saved author evidence only, not an independent replay. No rebuild.
"""
import hashlib
import sys
from pathlib import Path

SHA = {
    "h71.heif": "2c3b8667400880bd844373134932598ffe47fcb91011ee92e1cfc5e84c7a2bbb",
    "h72.heif": "259a985b2ee466c0fba1262c83b3304ad26441ca0585fbfcb9c0888abb937ac9",
    "h80.heif": "2793a2123a8b80fb751aa74b9f827afe0e78a7393c14f4ffc171a316773cdac4",
    "h96.heif": "f92fc8e960acc828b51526ba634b3f0b829d62282a26a368745f4d8271eff56d",
}


def main():
    here = Path(__file__).resolve().parent
    d = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "evidence/advisory-size"
    checks = []

    def text(name):
        return (d / name).read_text(errors="replace")

    def rc(name):
        return text(name).strip()

    for name, digest in SHA.items():
        got = hashlib.sha256((d / name).read_bytes()).hexdigest()
        checks.append((f"{name} sha256", got == digest, got))

    checks.append(("advisory plain rc=139", rc("plain-advisory.rc") == "139", rc("plain-advisory.rc")))
    checks.append(("advisory plain decodes mixed frames",
                   "frame 0 decoded: 512x72 stride=512" in text("plain-advisory.out") and
                   "frame 1 decoded: 64x512 stride=64" in text("plain-advisory.out"), ""))

    for h in (71, 72, 80, 96):
        want = "0" if h < 80 else "134"
        checks.append((f"h{h} plain rc={want}", rc(f"plain-h{h}.rc") == want, rc(f"plain-h{h}.rc")))
        checks.append((f"h{h} plain decoded height",
                       f"frame 1 decoded: 64x{h} stride=64" in text(f"plain-h{h}.out"), ""))
        want_asan = "0" if h < 80 else "1"
        checks.append((f"h{h} ASan rc={want_asan}",
                       rc(f"asan-h{h}.rc") == want_asan, rc(f"asan-h{h}.rc")))

    for h in (71, 72):
        out = text(f"asan-h{h}.out")
        checks.append((f"h{h} ASan clean and both frames encoded",
                       "AddressSanitizer" not in out and "frame 1 encoded" in out, ""))

    for h in (80, 96):
        out = text(f"asan-h{h}.out")
        checks.append((f"h{h} ASan OOB signature on 36879-byte region",
                       "heap-buffer-overflow" in out and "WRITE of size 64" in out and
                       "0 bytes after 36879-byte region" in out and "pixelimage.cc:644" in out, ""))
        checks.append((f"h{h} plain glibc metadata abort",
                       "free(): corrupted unsorted chunks" in text(f"plain-h{h}.out"), ""))

    for h in (71, 80):
        out = text(f"fixed-h{h}.out")
        checks.append((f"h{h} fixed pin rejects encode",
                       rc(f"fixed-h{h}.rc") == "0" and "encode: rc=2" in out and
                       "All frames of a sequence must have the size of the first frame" in out and
                       "AddressSanitizer" not in out, ""))

    gdb_attack = text("gdb-plain-advisory.out")
    checks.append(("advisory gdb fault inside the overflowing memcpy",
                   "received signal SIGSEGV" in gdb_attack and
                   "__memcpy_avx_unaligned_erms" in gdb_attack and
                   "in HeifPixelImage::extend_padding_to_size" in gdb_attack and
                   "in x265_encode_sequence_frame" in gdb_attack, ""))
    checks.append(("advisory gdb maps a heap region", "[heap]" in gdb_attack, ""))

    gdb_h80 = text("gdb-plain-h80.out")
    checks.append(("h80 gdb abort in old-plane free inside padding call",
                   "received signal SIGABRT" in gdb_h80 and
                   'free(): corrupted unsorted chunks' in gdb_h80 and
                   "malloc_printerr" in gdb_h80 and "__GI___libc_free" in gdb_h80 and
                   "in HeifPixelImage::extend_padding_to_size" in gdb_h80, ""))

    rep = text("plain-repeat.txt")
    checks.append(("repeat stability recorded",
                   "advisory rc 139 x3" in rep and "h80 rc 134 x3" in rep, ""))

    for name, ok, detail in checks:
        print(f"{'PASS' if ok else 'FAIL'} {name}" + (f" {detail}" if detail and not ok else ""))
    fails = sum(1 for _, ok, _ in checks if not ok)
    print(f"PASS={len(checks)-fails} FAIL={fails}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
