# frontier brief — mediainfolib2shell (candidate screened this wake, NOT staged)

## Ground truth (read-only provisioning, 2026-11-24 06:5xZ)

- Claim: VulnCheck 2026-11-23, CVE-2026-135440, CWE-416 (use-after-free),
  CVSS4 6.9 `AV:L/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:H`, MediaInfoLib < 26.10.
  Advisory:
  <https://www.vulncheck.com/advisories/mediainfolib-before-26.10-use-after-free-via-file-vorbis-setup>.
  Claimed primitive: a crafted Ogg/Vorbis file makes `File_Vorbis::Setup()`
  return early without `BS_End_LE()`, leaving a stale bitstream pointer that
  reads freed heap memory; the reporter's ASan trace shows a `READ of size 1`
  at `ZenLib/BitStream_LE.h:80`, 11 bytes into a freed 32,768-byte Ogg packet
  buffer, preceded by UBSAN `index 5888 out of bounds for type 'const
  int32u[33]'` at line 68. Credit: Alexander A. Shvedov (sigdevel).
- Upstream: issue <https://github.com/MediaArea/MediaInfoLib/issues/2613>,
  closed, and PR <https://github.com/MediaArea/MediaInfoLib/pull/2618>.
- Pinned vulnerable source: MediaInfoLib `v26.05` commit
  `f23e69ce89581343f3b7a42e06828a5331e290d5`; ZenLib HEAD at fetch
  `be7f11642c33094ce02cfa5ae077afdaf603a14c`. Pinned under
  `lab/frontier/mediainfolib2shell/`.
- Public PoC: `res/mediainfo/10/mediainfo_10`, 1248 bytes, SHA-256
  `af23be76c3c0e9b9d22bc2c5d7e997fd0c44e81b277f485d6414a0bb2a277b70`.
  Fix patch `fix-2618.patch`, SHA-256
  `c4ec046b9f5ce646266fa43320e8a201e0dd65f69de9466e6e703d606da36516`;
  relevant commits `6bacf12f0a7e5d72d7e46e4efb721f64b50348ba` (add
  `BS_End_LE()` before both early returns) and
  `2a13d1b98525bcf789472b4fd80562f8e1b0756b` (`BT->Attach(NULL, 0)` in
  `Buffer_Clear()` and `Data_Manage()`).

## Source-bound mechanism

In pinned `Source/MediaInfo/Audio/File_Vorbis.cpp`, `Setup()` calls
`BS_Begin_LE()` and then has two bare early returns: `if (codebook!=0x564342)
return;` and `if (codebook_lookup_type>2) return;`. Neither calls
`BS_End_LE()`, so `BT` stays attached to the old packet buffer when
`File__Analyze::Buffer_Clear()` deletes that buffer. The next
`BitStream_LE::Skip()`/`Get()` reads through the stale `ptr`
(`ZenLib/Source/ZenLib/BitStream_LE.h:80`). The two fix commits close both
sides: end the bitstream on early return and detach `BT` whenever the buffer
is cleared.

## Measured local negative (this wake)

A real ASan build was attempted, not just assumed: CMake/Ninja with
`-DCMAKE_BUILD_TYPE=Debug -DBUILD_ZENLIB=ON -DBUILD_SHARED_LIBS=OFF` and
`-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1`, `-j8`.
In 420 s (tool timeout, ended ~06:58Z) it reached **32 of 293 objects**;
`build-asan/libmediainfo.a` and `build-asan/ZenLib/libzen.a` do not exist,
`harness.cpp` (real `MediaInfoLib::MediaInfo::Open(path)` API) was never
linked, and no PoC was run. No ASan report, no crash, no observed bytes:
**rung UNKNOWN**, not a rung 1-4 claim. No system `mediainfo` binary is
installed; `valgrind` is available but needs a linked binary.

## Ranking and cheapest next experiment

Rank: LOW-MEDIUM tractability, LOW rung-4 ceiling. The public PoC is tiny and
the fixes are pinned, so a future wake with a longer build budget can finish
it, but the primitive is a stale **read**, not a write: it can disclose heap
bytes, not place chosen bytes at chosen offsets, so it is unlikely to reach
rung 4 as an X2Shell candidate. Cheapest experiment: reconfigure with
`-O0 -fsanitize=address` only (drop UBSan) and `-j$(nproc)`, optionally use
`ccache`; link `harness.cpp` against `libmediainfo.a`/`libzen.a`, run the
pinned PoC and check for `heap-use-after-free READ` at
`BitStream_LE.h:80`; then apply pinned commits `6bacf12f` and `2a13d1b9` as
controls and require a clean run. Preserve the build log if it fails again.

## Ceiling / UNKNOWNs

No window, witness request or admission is owed. Build feasibility at `-O0`
and the fixed-control result remain UNKNOWN. Do not stage this target without
an observed ASan report. Do not duplicate a later admission of this target.
