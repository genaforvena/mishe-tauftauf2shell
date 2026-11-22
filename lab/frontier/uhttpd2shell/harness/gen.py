#!/usr/bin/env python3
"""Extract uh_ubus_send_request() verbatim from the pinned uhttpd sources.

Usage:
  gen.py PIN              write pins/PIN_fn.inc (and the active fn.inc)
  gen.py PIN --stdout     emit the extracted, renamed function to stdout
  gen.py PIN --verify     compare the stored include with a fresh git show
  gen.py hashes           (re)write pins/PIN_HASHES.txt

PIN is 'vuln' or 'fixed'.  The only transformation applied to the pinned
function is the rename uh_ubus_send_request -> PIN_uh_ubus_send_request;
every other byte of the function (including the signature line) is copied
from `git show SHA:ubus.c` in the local clone.
"""
import hashlib
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
PINS = HERE / "pins"
UHTTPD = HERE.parent / "src" / "uhttpd"
LIBUBOX = HERE.parent / "src" / "libubox"

PIN_SHA = {
    "vuln": "f682ccabee9ed5f39dd3b0aaf96228975eeb478d",
    "fixed": "e76736e5676fb25536b27d45865eb4153c68aca3",
}
LIBUBOX_SHA = "a396f38a8568a1d670c240465cd8d24fdfdf6463"
SIGNATURE = "static void uh_ubus_send_request("


def pinned_source(pin):
    """Read the committed pinned ubus.c blob; fall back to the local clone."""
    blob = PINS / ("ubus-vuln.c" if pin == "vuln" else "ubus-fixed.c")
    if blob.is_file():
        return blob.read_text()
    out = subprocess.check_output(
        ["git", "show", f"{PIN_SHA[pin]}:ubus.c"], cwd=UHTTPD
    )
    return out.decode("utf-8")


def extract(text, pin):
    """Return the pinned function, byte-for-byte, with only the name renamed."""
    lines = text.splitlines(keepends=True)
    start = next(i for i, ln in enumerate(lines) if ln.startswith(SIGNATURE))
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}\n")
    fn = "".join(lines[start:end + 1])
    renamed = fn.replace(SIGNATURE, f"static void {pin}_uh_ubus_send_request(", 1)
    if renamed == fn:
        raise RuntimeError("function rename failed")
    return renamed


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def update_hashes():
    lines = [
        f"# uhttpd GHSA-2mpg-6wp5-435p harness pin hashes",
        f"# uhttpd vuln pin: {PIN_SHA['vuln']}",
        f"# uhttpd fixed pin: {PIN_SHA['fixed']}",
        f"# libubox pin: {LIBUBOX_SHA}",
        "# All hashes are sha256 of the exact bytes used by the build.",
    ]
    for name in ("vuln_fn.inc", "fixed_fn.inc", "blob.c", "blobmsg.c",
                 "blob.h", "blobmsg.h", "utils.h"):
        p = PINS / name
        if p.exists():
            lines.append(f"{sha256_file(p)}  {name}")
    (PINS / "PIN_HASHES.txt").write_text("\n".join(lines) + "\n")


def main():
    args = sys.argv[1:]
    if len(args) == 1 and args[0] == "hashes":
        update_hashes()
        print(f"wrote {PINS / 'PIN_HASHES.txt'}")
        return 0
    if not args or args[0] not in PIN_SHA:
        print(__doc__)
        return 2
    pin = args[0]
    mode = args[1] if len(args) > 1 else "write"
    if mode not in ("write", "--stdout", "--verify"):
        print(__doc__)
        return 2

    expected = extract(pinned_source(pin), pin)
    target = PINS / f"{pin}_fn.inc"

    if mode == "--stdout":
        sys.stdout.write(expected)
        return 0

    if mode == "--verify":
        if not target.exists():
            print(f"VERIFY {pin} MISSING {target}")
            return 1
        got = target.read_text()
        ok = got == expected
        status = "OK" if ok else "MISMATCH"
        print(f"VERIFY {pin} {status} sha256={hashlib.sha256(got.encode()).hexdigest()} "
              f"source_sha={PIN_SHA[pin]}")
        if not ok:
            for i, (a, b) in enumerate(zip(got.splitlines(), expected.splitlines()), 1):
                if a != b:
                    print(f"  line {i}: stored={a!r} expected={b!r}")
                    break
        return 0 if ok else 1

    target.write_text(expected)
    (HERE / "fn.inc").write_text(expected)
    update_hashes()
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
