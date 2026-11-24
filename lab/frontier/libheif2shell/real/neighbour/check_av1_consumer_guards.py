#!/usr/bin/env python3
"""W201: source guards that keep the AV1 consumer paths off the padding write.

W189 rejected the ImageMagick AVIF-sequence hypothesis because AV1 selects AOM,
which has no padding call. That conclusion could be build-specific: pinned
v1.23.6 also has the padding call in the SVT-AV1 plugin. This checker closes
the gap from pinned source:

  * AOM priority 60 outranks SVT priority 40, and the descriptor set is ordered
    highest-priority first, so ImageMagick's unnamed encoder request picks AOM
    even in a build that includes SVT.
  * libheif's own heif-enc CLI, which CAN select an encoder by name, rejects a
    sequence frame whose size differs from the first frame before encoding it.

Usage: check_av1_consumer_guards.py [LIBHEIF_SRC] [IM HEIC.C]
Defaults are the pinned source trees in this plant. Both trees are gitignored;
a clean `git archive` replay must pass both paths as arguments. Source-level
only: no build, no process, no wire input, no new rung.
"""
import re
import sys
from pathlib import Path


def text(path):
    return path.read_text(errors="replace")


def priority(src, plugin, default=None):
    m = re.search(rf"{plugin}_PLUGIN_PRIORITY\s*=\s*(\d+)", src)
    return int(m.group(1)) if m else default


def main():
    here = Path(__file__).resolve().parent
    root = here.parents[4]
    heif_src = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        root / "lab/frontier/libheif2shell/src/libheif-v1.23.6")
    im_c = Path(sys.argv[2]) if len(sys.argv) > 2 else (
        root / "lab/frontier/imagemagick2shell/vuln/coders/heic.c")

    aom = priority(text(heif_src / "libheif/plugins/encoder_aom.cc"), "AOM")
    svt = priority(text(heif_src / "libheif/plugins/encoder_svt.cc"), "SVT")
    svt_src = text(heif_src / "libheif/plugins/encoder_svt.cc")
    aom_src = text(heif_src / "libheif/plugins/encoder_aom.cc")
    registry = text(heif_src / "libheif/plugin_registry.h")
    encoding = text(heif_src / "libheif/api/libheif/heif_encoding.cc")
    cli = text(heif_src / "examples/heif_enc.cc")
    im = text(im_c)

    checks = [
        ("AOM priority parsed", aom is not None, aom),
        ("SVT priority parsed", svt is not None, svt),
        ("AOM outranks SVT", aom is not None and svt is not None and aom > svt,
         f"AOM={aom} SVT={svt}"),
        ("descriptor set is highest-priority-first",
         "a->plugin->priority > b->plugin->priority" in registry, ""),
        ("unnamed encoder request takes descriptors[0]",
         "get_filtered_encoder_descriptors(format, nullptr)" in encoding
         and "*encoder = new heif_encoder(descriptors[0]->plugin)" in encoding, ""),
        ("ImageMagick sequence writer requests AV1 without a name",
         "heif_context_get_encoder_for_format(heif_context,\n    heif_compression_AV1,&heif_encoder)" in im, ""),
        ("SVT plugin has the padding call", "extend_padding_to_size" in svt_src, ""),
        ("AOM plugin has no padding call", "extend_padding_to_size" not in aom_src, ""),
        ("heif-enc can select an encoder by name",
         "heif_context_get_encoder(context.get(), encoder_descriptors[idx], &encoder)" in cli, ""),
        ("heif-enc sequence rejects a size mismatch before encoding",
         "image_width != static_cast<uint16_t>(w)" in cli
         and "image_height != static_cast<uint16_t>(h)" in cli
         and "different from the first image size" in cli, ""),
    ]

    for name, ok, detail in checks:
        print(f"{'PASS' if ok else 'FAIL'} {name}" + (f" [{detail}]" if detail else ""))
    fails = sum(1 for _, ok, _ in checks if not ok)
    print(f"PASS={len(checks)-fails} FAIL={fails}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
