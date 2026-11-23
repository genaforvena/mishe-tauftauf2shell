# Frontier brief: ImageMagick stream pixel-buffer reuse (imagemagick2shell)

**STAGED 2026-11-23 W183.** This brief, a pinned vulnerable/fixed/plain lab
with a replayable evidence matrix, and a registered two-pane target window
exist. Claim sources, exact pins and the replay are below. No external system
was probed; all inputs are local.

## 1. Verified ground truth (claims, not acceptance)

- NVD/CVE record `CVE-2026-130664`, CNA VulnCheck, published 2026-11-18,
  "ImageMagick before 7.1.2-35 contains a heap buffer overflow vulnerability
  that allows attackers to write beyond allocated heap memory by supplying
  crafted images. Attackers can provide a crafted set of images processed by
  the `magick stream` operation to corrupt heap memory and crash the
  application." CWE-787; CVSS 3.1 **2.5 LOW**
  `AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L`, CVSS 4.0 2.0 LOW. Affected
  7.0.0 before 7.1.2-35 and 6.x before 6.9.13-60; unaffected at 7.1.2-35 /
  6.9.13-60. Credit: aserper. The availability-only wording is the CNA's;
  the broader "code execution" prose seen in CVE-feed aggregators is not in
  the vendor advisory and is **UNKNOWN** here.
- Vendor advisory GHSA-3pf7-cjfr-3fpq (ImageMagick, published 2026-11-01):
  "A crafted set of images could cause a heap buffer over write in the
  magick stream operation." Severity LOW, CWE-787. No PoC is attached to the
  public advisory.
- Fix commit `6b833ce613bc` (2026-10-19, one file `MagickCore/stream.c`,
  +5/-1, parent `9dd13eabba07`) is the only commit in the 7.1.2-34..35 range
  that carries this advisory's ID. A later, separate hardening commit
  `e41876eb4ad4` (GHSA-4cmr-g39q-mh38) adds extract-region clamping in the
  same function; that hunk is **not** attributed to this CVE.

## 2. Source-bound mechanism

Pinned `vuln/MagickCore/stream.c` (7.1.2-34, SHA-256 in `PINS.sha256`):

- `:1250` `length=packet_size*cache_info->columns*cache_info->rows;`
- `:1251-1264` reallocates `stream_info->pixels` to `length` and records
  `stream_info->image=image` **only when the image pointer changes**.
- `:1279` `StreamImagePixels(...)` converts the pixel queue into
  `stream_info->pixels`, writing `GetImageExtent(image)` pixels through a
  `q` pointer with no bound tied to the original allocation.
- `:924-940` in `QueueAuthenticPixelsStream()` calls the stream handler with
  the *image* geometry on a morphology change, then overwrites
  `cache_info->columns/rows` with the *requested region* geometry.
- `:2778` `SyncAuthenticPixelsStream()` calls the same handler with the
  region geometry. When the region is larger but `image` is unchanged, the
  guard at `:1251` is false, so the old buffer is reused and `:1279` writes
  past it.

Upstream fix adds a `size_t length` field to `StreamInfo`, changes the guard
to `(image != stream_info->image) || (length > stream_info->length)`, and
records `stream_info->length=length` after allocation. The pinned 7.1.2-35
`stream.c` has it; the local fixed build is that unmodified tag.

## 3. Local experiment

`lab/frontier/imagemagick2shell/`:

- Pinned source tarballs `ImageMagick-7.1.2-34.tar.gz` and
  `ImageMagick-7.1.2-35.tar.gz`, extracted as `vuln/` and `fixed/`; hashes in
  `PINS.sha256` together with both `MagickCore/stream.c` blobs and the
  harness. Builds use static-only autotools with all image delegates off.
- `harness.c` includes the pinned `MagickCore/stream.c` so it can drive the
  library's real file-static handlers `QueueAuthenticPixelsStream` and
  `SyncAuthenticPixelsStream`. `OpenBlob(...,WriteBinaryBlobMode,...)` installs
  the handler on the image exactly as `ReadStream()` does. A small first
  queue allocates the buffer; a larger second queue plus a real pixel queue
  filled with chosen quantum values makes the sync path write past it.
- `run-all.sh` rebuilds three harnesses (vulnerable ASan, fixed ASan, plain)
  and replays a same-size control and a 1x1 -> 8x4 attack on each, then a gdb
  chosen-byte read on the plain attack. Transcript `evidence.log` SHA-256
  `e5f2c27bc021ab1e96b35db04ca9425758ba69ffc8bc04fa65e34879644028d5`,
  2026-11-23T23:05:32Z. All five pins pass `sha256sum -c`.

Measured:

1. Vulnerable ASan harness, same-size control (2x2 -> 2x2): rc 0, no ASan
   report; the three-byte-per-pixel buffer contains the chosen pattern
   `41 41 41 42 42 42 43 43 43 44 44 44`.
2. Vulnerable ASan harness, attack (1x1 -> 8x4): rc 1,
   `AddressSanitizer: heap-buffer-overflow`, `WRITE of size 1`, `0 bytes
   after 3-byte region`, stack `StreamImagePixels stream.c:1576` ←
   `WriteStreamImage stream.c:1279` ← `SyncAuthenticPixelsStream:2778` ←
   harness. Allocation stack: `posix_memalign` ← `AcquireAlignedMemory` ←
   `WriteStreamImage:1260` ← `QueueAuthenticPixelsStream:927`.
3. Fixed ASan harness (unmodified 7.1.2-35 tag): same-size control and the
   identical 1x1 -> 8x4 attack both rc 0 with **no ASan report**; the fixed
   guard reallocates before the enlarged region is written.
4. Plain vulnerable harness, attack under gdb at the line following sync:
   `stream_info->pixels[0..23] = 41 41 41 42 42 42 43 43 43 44 44 44
   45 45 45 46 46 46 47 47 47 48 48 48` — chosen bytes `0x42..0x48` sit at
   offsets 3 through 23, entirely past the 3-byte allocation. `x/s` renders
   `AAABBBCCCDDDEEEFFF...`. Under Q16 HDRI the harness sets each quantum to
   `byte*257`, so the resulting byte is a direct function of the input pixel.
5. The plain-build same-size control also exits rc 0 with the original
   three-byte pattern; the failure is specific to region growth.

## 4. Rung-4 feasibility and grade

**Rung 1** (deterministic trigger), **rung 2** (observed geometry/state
failure: 1x1 allocation with 8x4 region, `image == stream_info->image`),
**rung 3** (ASan-confirmed heap WRITE in `StreamImagePixels`) and **rung 4**
(chosen pixel bytes at chosen offsets past the allocation) are met by driving
the real ImageMagick stream cache handlers with real pixel-queue data.

**Ceiling / UNKNOWN:** this is a direct-call/in-process harness against the
real library, not the `magick stream` CLI: no crafted image file, no decoder
path, no server, socket or wire, no allocator grooming into a live object, no
pointer/IP control, no command, no witness replay, no rung 5. The advisory's
"crafted set of images" reachability through a specific coder is not
reproduced here and stays UNKNOWN. The vulnerability's CVSS is LOW and
availability-only; this brief ranks it by tractability, not by hype.

## 5. Cheapest next steps for a dedicated mind

1. Replay `sh lab/frontier/imagemagick2shell/run-all.sh` in a clean archive
   and request an independent witness reproduction of the ASan WRITE and the
   chosen-byte line.
2. Find the actual coder whose `QueueAuthenticPixels()` region can exceed the
   first image geometry under attacker control, and reproduce the same
   overflow through `magick stream` on a crafted image file. Until that
   exists, do not claim file reachability.
3. On the plain build, groom a live object immediately after the 3-byte
   stream buffer and show a chosen pointer-shaped value or deterministic
   crash; measure ASLR before any control-flow claim. Do not infer RCE.

## 6. Ranking

Moderate tractability: a small, exact upstream one-line fix and a pinned C
file make the bug easy to isolate, and the harness needs no third-party
image codec. Ranked below targets with a demonstrated wire or file-consumer
path (e.g. busybox2shell) because the public advisory provides no PoC and the
CLI reachability is still UNKNOWN. Operator owns admission.
