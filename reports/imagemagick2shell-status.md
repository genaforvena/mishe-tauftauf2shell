# imagemagick2shell — status

Admitted 2026-11-24 00:3xZ under standing #6 as the 123rd route. Claim:
`CVE-2026-130664` (VulnCheck CNA, published 2026-11-18, CWE-787, CVSS 3.1
2.5 LOW `AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L`, CVSS 4.0 2.0 LOW, credit
aserper) and `GHSA-3pf7-cjfr-3fpq` (ImageMagick, 2026-11-01, LOW, no PoC).
A crafted set of images processed by `magick stream` writes past a heap
buffer; affected 7.0.0 before 7.1.2-35 and 6.x before 6.9.13-60, fixed at
7.1.2-35 / 6.9.13-60 by the one-line `MagickCore/stream.c` commit
`6b833ce613bc`. Stage: real-library direct-call rungs 1-4; unwitnessed;
file reachability and rung 5 UNKNOWN.

## Admission evidence

- Frontier brief `reports/frontier-imagemagick2shell.md` (staged W183) pins
  both advisory records, the fix commit, both source tarballs, both
  `MagickCore/stream.c` blobs and the harness in
  `lab/frontier/imagemagick2shell/PINS.sha256` (five SHA-256 values).
- Operator verification 00:28Z: `lab/frontier/imagemagick2shell/REPLAY.log`
  SHA-256 `385bbe95d648dd19981d0d42df483c9ebeb619bb078fd3a2a2c9789bac01667a`
  verified directly. It is the clean `git archive 7873caf` replay of
  `bootstrap.sh`/`run-all.sh`: all pins pass, vulnerable ASan reports
  `WRITE of size 1` 0 bytes after a 3-byte region at `stream.c:1576`,
  same-size control and unmodified fixed-tag build exit 0 ASan-clean, and
  the plain-build gdb read shows chosen bytes `0x42..0x48` at offsets 3..23.
  This is deterministic replay of the author's harness, not witness
  acceptance.
- Minted under the exact full-flag sync from `docs/runtime-pin.md:96-102`
  with pin `0d686bbad55c849e88334da64efff9da88ad528a`: `written 3, removed 0`;
  `m2shell-wake-imagemagick2shell.path` enabled and active after
  daemon-reload; pinned full-flag doctor `GREEN`, exit 0. Route count
  122→123 (hy4-flash, `max_parallel: 3`); resolver 245→247 (both wake keys
  → operator). The two-pane window at index 127 was created by frontier at
  23:06Z and adopted, not duplicated.

## Current grade

Rungs 1-4 by direct calls into the real `MagickCore` stream cache handlers
with real pixel-queue data, not through the CLI:

1. Deterministic trigger — a 1x1 first queue allocates the 3-byte-per-pixel
   stream buffer; an 8x4 region on the same `image` triggers the write.
2. Observed state failure — `image == stream_info->image` while
   `cache_info->columns/rows` changed from the image geometry to the
   requested region (1x1 → 8x4), so the realloc guard at `stream.c:1251`
   is false.
3. Confirmed corruption — ASan `heap-buffer-overflow`, `WRITE of size 1`,
   0 bytes after a 3-byte region allocated by `posix_memalign` via
   `AcquireAlignedMemory` in `WriteStreamImage:1260`; write through
   `StreamImagePixels stream.c:1576` ← `WriteStreamImage:1279` ←
   `SyncAuthenticPixelsStream:2778`.
4. Placement control — Q16 HDRI pixel values map directly to output bytes;
   gdb shows `41 41 41 42 42 42 … 48 48 48` in `stream_info->pixels[0..23]`,
   i.e. chosen `0x42..0x48` at offsets 3..23, entirely past the allocation.

Same-size controls (2x2 → 2x2) exit 0 with the original three-byte pattern
on both vulnerable and plain builds; the unmodified 7.1.2-35 fixed-tag
build is rc 0 and ASan-clean on the identical attack.

No crafted image file, coder or decoder path, `magick stream` CLI, server,
socket or wire, no allocator grooming into a live object, no pointer/IP
control, no command, no witness verdict and no rung 5. The advisory's
"crafted set of images" reachability through any specific coder is
**UNKNOWN**, not reproduced. The advisory is availability-only and CVSS LOW;
the ranking here is by tractability, not by severity claim.

## Next for the target mind

1. Request witness replay of the ASan WRITE and chosen-byte legs; the author
   report is not acceptance.
2. Identify the coder whose `QueueAuthenticPixels()` region can exceed the
   first image geometry and reproduce the fault through the CLI on a crafted
   image file before claiming file reachability.
3. On the plain build, groom a live object immediately after the 3-byte
   buffer and measure ASLR and pointer-shaped values before any control-flow
   claim. Never infer RCE from a crash; hand any new claim to `witness`.
