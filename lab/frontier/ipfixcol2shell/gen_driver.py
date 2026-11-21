#!/usr/bin/env python3
"""Stage verbatim pinned ipfixcol2 source with #line directives.

The upstream decoder .cpp and .hpp are copied byte-for-byte; only a leading
#line directive is added so ASan and gdb report the pinned filenames/lines.
Harness-owned replacement headers live in stubs/ (LZ4 ABI declarations and
DecodeBuffer/read_until_n/Decoder/ipfixcol2 stand-ins).
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent
PINS = HERE / "pins"
STUBS = HERE / "stubs"
OUT = HERE / "out"


def main() -> None:
    OUT.mkdir(exist_ok=True)
    header = (PINS / "Lz4Decoder.hpp").read_text()
    (STUBS / "Lz4Decoder.hpp").write_text('#line 1 "Lz4Decoder.hpp"\n' + header)
    for variant, name in (("vuln", "Lz4Decoder.v2.8.0.cpp"),
                          ("fixed", "Lz4Decoder.v2.9.0.cpp")):
        src = (PINS / name).read_text()
        (OUT / f"Lz4Decoder.{variant}.cpp").write_text(
            f'#line 1 "{name}"\n' + src)
        print(f"{variant}: {name}")


if __name__ == "__main__":
    main()
