#!/usr/bin/env python3
"""W202: close the named-HEVC-encoder consumer lane from pinned source.

The remaining research lane after W189/W201 was: a real consumer that NAMES an
HEVC-family encoder for a sequence and has no same-size guard. Pinned source
shows why no consumer in this plant can be that lane:

  * The x265/x264/kvazaar plugins feed the encoder-open dimensions
    (encoder->param->sourceWidth/sourceHeight) into the padding call for EVERY
    frame, so a frame whose own dimensions differ is the trigger.
  * The library's heif_track_encode_sequence_image() has no size guard; the
    mixed-size rejection lives only in the heif-enc CLI.
  * heif-enc is the only in-tree CLI that can name an encoder, and it rejects
    mismatched frames before calling the library.
  * ImageMagick's sequence writer requests AV1 by format, not by name, so AOM
    (which has no padding call) wins; libvips encodes single images only.

Usage: check_named_encoder_lane.py [LIBHEIF_SRC] [IM HEIC.C] [VIPS HEIFSAVE.C]
Defaults are the pinned source trees in this plant. All three trees are
gitignored; a clean `git archive` replay must pass all three paths.
Source-level only: no build, no process, no wire input, no new rung.
"""
import sys
from pathlib import Path


def text(path):
    return path.read_text(errors="replace")


def function_span(src, signature, marker):
    start = src.find(signature)
    if start < 0:
        return ""
    end = src.find(marker, start)
    return src[start:end] if end > start else ""


def main():
    here = Path(__file__).resolve().parent
    root = here.parents[4]
    heif_src = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        root / "lab/frontier/libheif2shell/src/libheif-v1.23.6")
    im_c = Path(sys.argv[2]) if len(sys.argv) > 2 else (
        root / "lab/frontier/imagemagick2shell/vuln/coders/heic.c")
    vips_c = Path(sys.argv[3]) if len(sys.argv) > 3 else (
        root / "lab/frontier/libvips2shell/src/libvips-8.18.2/libvips/foreign/heifsave.c")

    x265 = text(heif_src / "libheif/plugins/encoder_x265.cc")
    x264 = text(heif_src / "libheif/plugins/encoder_x264.cc")
    kvazaar = text(heif_src / "libheif/plugins/encoder_kvazaar.cc")
    aom = text(heif_src / "libheif/plugins/encoder_aom.cc")
    api_image = text(heif_src / "libheif/api/libheif/heif_image.cc")
    sequences = text(heif_src / "libheif/api/libheif/heif_sequences.cc")
    cli = text(heif_src / "examples/heif_enc.cc")
    im = text(im_c)
    vips = text(vips_c)

    mismatch = "encoder->param->sourceWidth,\n                                          encoder->param->sourceHeight)"
    seq_body = function_span(sequences,
                             "heif_error heif_track_encode_sequence_image(",
                             "visual_track->encode_image(")

    x264_mismatch = "param.i_width,\n                                          param.i_height)"
    # kvazaar's padding call sits inside a /* ... */ block in v1.23.6: not live.
    kvazaar_commented = "/*\n  err = heif_image_extend_padding_to_size" in kvazaar
    checks = [
        ("x265 pads each frame to encoder-open dimensions",
         mismatch in x265, ""),
        ("x264 pads each frame to encoder-open dimensions",
         x264_mismatch in x264, ""),
        ("kvazaar padding call is disabled in this pin",
         kvazaar_commented, ""),
        ("public padding wrapper reaches HeifPixelImage::extend_padding_to_size",
         "image->image->extend_padding_to_size(min_physical_width, min_physical_height," in api_image, ""),
        ("AOM plugin has no padding call", "extend_padding_to_size" not in aom, ""),
        ("library sequence encode has no size guard",
         bool(seq_body) and "get_width(" not in seq_body and "get_height(" not in seq_body,
         f"span={len(seq_body)}"),
        ("heif-enc sequence path calls the library sequence API",
         "heif_track_encode_sequence_image(track, image.get(), encoder, encoding_options)" in cli, ""),
        ("heif-enc rejects a mixed-size frame before encoding",
         "image_width != static_cast<uint16_t>(w)" in cli
         and "image_height != static_cast<uint16_t>(h)" in cli
         and "different from the first image size" in cli, ""),
        ("ImageMagick sequence writer requests AV1 by format, not by name",
         "heif_context_get_encoder_for_format(heif_context,\n    heif_compression_AV1,&heif_encoder)" in im, ""),
        ("libvips encodes single images only",
         "heif_context_encode_image(heif->ctx," in vips
         and "heif_track_encode_sequence_image" not in vips
         and "heif_context_add_visual_sequence_track" not in vips, ""),
    ]

    for name, ok, detail in checks:
        print(f"{'PASS' if ok else 'FAIL'} {name}" + (f" [{detail}]" if detail else ""))
    fails = sum(1 for _, ok, _ in checks if not ok)
    print(f"PASS={len(checks)-fails} FAIL={fails}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
