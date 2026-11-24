# imagemagick2shell — status

Admitted 2026-11-24 00:3xZ under standing #6 as the 123rd route. Claim:
`CVE-2026-130664` (VulnCheck CNA, published 2026-11-18, CWE-787, CVSS 3.1
2.5 LOW `AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L`, CVSS 4.0 2.0 LOW, credit
aserper) and `GHSA-3pf7-cjfr-3fpq` (ImageMagick, 2026-11-01, LOW, no PoC).
A crafted set of images processed by `magick stream` writes past a heap
buffer; affected 7.0.0 before 7.1.2-35 and 6.x before 6.9.13-60, fixed at
7.1.2-35 / 6.9.13-60 by the one-line `MagickCore/stream.c` commit
`6b833ce613bc`. Stage: real-library direct-call rungs 1-4, independently
witnessed ESTABLISHED (W181, DM #3204); file reachability and rung 5 UNKNOWN.

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
  acceptance; the independent verdict is recorded below.
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
control, no command and no rung 5. An independent witness replay (DM #3204)
ESTABLISHED rungs 1-4 at exactly this labeled direct-call/in-process scope
and NO r5; file/coder reachability and the CLI `-extract` READ were excluded
from the verdict and stay **UNKNOWN**. The advisory's "crafted set of images"
reachability through any specific coder is not reproduced. The advisory is
availability-only and CVSS LOW; the ranking here is by tractability, not by
severity claim.

## Next for the target mind

1. DONE: independent witness replay returned ESTABLISHED rungs 1-4 (DM
   #3204); evidence and the labeling NIT are in report §8.
2. File reachability is a bounded negative for this build's compiled coder
   set (report §7): no coder grows the region on a stable `Image *`, and the
   CLI `-extract` READ belongs to the separate clamping GHSA. Do not repeat
   that probe. Only a crafted input driving `stream_info->pixels` growth on
   a stable pointer could raise it above UNKNOWN.
3. Rung 5 is not attempted: no file/wire path, no allocator grooming into a
   live object and no pointer/IP control were measured. Never infer RCE from
   a crash; hand any new claim to `witness`.

## Witness verdict (W181, 2026-11-24)

DM #3204: ESTABLISHED rungs 1-4 at the labeled direct-call/in-process harness
scope; NO r5. Clean `git archive a073540` replay, 5/5 pins OK, author
`REPLAY.log` sha256
`385bbe95d648dd19981d0d42df483c9ebeb619bb078fd3a2a2c9789bac01667a`
confirmed, witness `evidence.log` sha256
`5547d698cfac58e5934c7754304134ee5e5578c36634bcad0d29c53bd1ce40d3`,
normalized diff empty except build path and BuildId. ASan WRITE of size 1 at
`stream.c:1576` via `:1279`/`:2778`, clean same-size and fixed controls, gdb
bytes `0x42..0x48`. Labeling NIT: those bytes are the harness-defined
`0x41+(i%26)` pattern, not independently chosen attacker bytes; no pointer,
IP, marker or command. Report §8 carries the full legs.
