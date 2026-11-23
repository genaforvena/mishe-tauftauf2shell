# Provenance — imagemagick2shell

All bytes came from public provisioning reads; no external system was probed.

- CVE-2026-130664 record: https://www.cve.org/CVERecord?id=CVE-2026-130664
  (CNA VulnCheck, published 2026-11-18, LOW 2.5
  `CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L`, CWE-787; affected
  7.0.0 before 7.1.2-35 and 6.x before 6.9.13-60; fixed 7.1.2-35 /
  6.9.13-60; reporter aserper).
- Vendor advisory: https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-3pf7-cjfr-3fpq
  ("A crafted set of images could cause a heap buffer over write in the
  magick stream operation").
- Fix commit: `6b833ce613bc` in ImageMagick/ImageMagick, 2026-10-19,
  "https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-3pf7-cjfr-3fpq",
  one file `MagickCore/stream.c`, +5/-1. Parent `9dd13eabba07`.
  A later unrelated hardening commit `e41876eb4ad4` (GHSA-4cmr-g39q-mh38,
  "Added missing overflow checks") adds the extract-region clamping in the
  same function; that hunk is NOT part of this CVE's fix and is excluded
  from the causal claim.
- Source pins: GitHub release tarballs for tags `7.1.2-34` and `7.1.2-35`,
  `https://github.com/ImageMagick/ImageMagick/archive/refs/tags/<tag>.tar.gz`,
  hashed in `PINS.sha256`. Extracted as `vuln/` and `fixed/` respectively.
  The pinned `MagickCore/stream.c` blobs are the exact pre/post states of
  the fix.
- Public tag comparison diff (`7.1.2-34...7.1.2-35.diff`) was read only to
  locate the fix; it is not part of the lab and is not required to replay.
- Builds: local autotools, static only, all optional image delegates off
  (no PNG/JPEG/TIFF/XML/zlib/etc.), no X, no Magick++. ASan builds use
  `-g -O1 -fsanitize=address -fno-omit-frame-pointer` and
  `-fsanitize=address` at link; the plain build uses `-g -O0`.
- Harness `harness.c` includes the pinned `MagickCore/stream.c` directly so
  it can drive the real file-static cache handlers
  `QueueAuthenticPixelsStream` and `SyncAuthenticPixelsStream` from the
  library build itself. It links against the corresponding static library;
  the linker does not pull `stream.o` from the archive because the harness
  object already defines those symbols. No source is modified in the lab.
- `bootstrap.sh` extracts both pinned tarballs into `vuln/` and `fixed/`,
  extracts a second vulnerable copy into `plain-src/`, builds all three
  configurations with the flags above and calls `run-all.sh`. It is the
  single command for a clean `git archive HEAD` replay; build/source bulk is
  gitignored, so the tarballs plus the harness are sufficient to rebuild
  every artifact.
- No fixed-tree code was backported into the vulnerable tree; the fixed
  result comes from building the real 7.1.2-35 tag.
