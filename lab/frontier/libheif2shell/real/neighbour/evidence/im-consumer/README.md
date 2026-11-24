# ImageMagick HEIF/AVIF consumer observation — W189 (2026-11-24)

Correction to W188. W188 found a real HEIF **sequence** writer in the plant's
ImageMagick 7.1.2-34 source and hypothesised it could supply the mixed-size
mismatch. It cannot: the sequence writer is AV1-only, and the vulnerable
padding call exists only in the HEVC-family encoder plugins.

## Build (all paths in /tmp; no peer tree modified)

Pinned vulnerable libheif `v1.23.6` static build from W161:
`/tmp/libheif2shell-vuln-plain/libheif/libheif.a`, with its `libheif/api`
headers and x265 sequence symbols. The ImageMagick source copy came from
`lab/frontier/imagemagick2shell/vuln` (read only) into `/tmp/w197-im-heic`.

    HEIF_CFLAGS=-I<libheif-v1.23.6>/libheif/api \
    HEIF_LIBS='<libheif.a> <heifio.a> <libheif.a> -ldl -lx265 -lde265 -laom ...' \
      ./configure --with-heic=yes --without-x --disable-shared --enable-static ...
    make -j8 utilities/magick \
      HEIF_CFLAGS=... HEIF_LIBS=... \
      MAGICK_DEP_LIBS='<deps without -lheif>' MAGICK_LIBS='...' LIBS='<libheif.a ...>'

`configure` initially selected the host `-lheif` 1.17.6 despite the environment
variables (`configure.log`); the Makefile variables had to be overridden on the
`make` command line (`make.log`, plus make3-make5 in the wake log). The final
binary links **no** `libheif.so` and reports `HEIC rw+` in `magick -list format`.

## Input and observed output

`mixed-frames.miff` SHA-256
`73590bbd702820ebebba3c9e490f694fdbd5cfdcc1281f6ca92958eed71f392d`;
`magick identify` reports `[0] 512x64` and `[1] 64x65` — the mismatch shape
used throughout this lane. Commands (with `MAGICK_HOME=/tmp/w197-im-heic` and
`MAGICK_CONFIGURE_PATH=/tmp/w197-im-heic/config`):

    magick mixed-frames.miff out.heic      # rc 0, heif-info: two still images 512x64 + 64x65
    magick mixed-frames.miff out.avif      # rc 0, heif-info: 512x64 + 64x65

The AVIF output is byte-repeatable with SHA-256
`f55d29b73d4136567e9994f2f06e9ca20fbe54d92d8f4f028bd00bd64156827e`.
`gdb-dispatch.out` sees `magick=AVIF adjoin=1 next!=0` at `heic.c:2513`, so the
sequence branch is eligible, and the AVIF `heif-info` output proves both
mixed-size frames were encoded. No ASan report, no crash, rc 0.

## Why this is a negative

- `heic.c:2516-2547` dispatches to `WriteHEICSequenceImage` only when
  `encode_avif` is true; `heic.c:2513-2514` sets that from output format AVIF.
  A `.heic` output takes the still-image loop instead (`heic.c:2549-2750`,
  `heif_context_encode_image` at `:2726`), so no sequence-size mismatch.
- `WriteHEICSequenceImage` selects `heif_compression_AV1` at
  `heic.c:2141-2142`. In pinned `v1.23.6`, `extend_padding_to_size` appears in
  `plugins/encoder_{x265,x264,kvazaar,svt,uvg266,vvenc}.cc` and the public API
  wrapper only; there is **no** call in the AOM/AV1 encoder. Thus the real AVIF
  sequence path cannot reach the vulnerable write.

`gdb-padding.out` must NOT be read as a clean-breakpoint negative: two copies of
the static libheif archive were linked (into MagickCore and into the final CLI),
so the breakpoint may have been placed on the unused copy. The negative rests on
the source call-graph plus the observed AV1 encode and rc 0.

Grade UNCHANGED rung 3+4, NOT rung 5. No wire request, chosen bytes at the
overflow, pointer control, command or witness verdict. Replay with
`python3 check_im_consumer.py .` from this directory.
