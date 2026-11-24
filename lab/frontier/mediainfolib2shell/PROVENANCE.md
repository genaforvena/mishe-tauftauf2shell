# mediainfolib2shell lab provenance

- Claim: VulnCheck 2026-11-23 CVE-2026-135440, CWE-416, CVSS4 6.9
  `AV:L/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:H`, MediaInfoLib < 26.10,
  "Use-After-Free via File_Vorbis::Setup". Advisory:
  <https://www.vulncheck.com/advisories/mediainfolib-before-26.10-use-after-free-via-file-vorbis-setup>.
  Upstream issue: <https://github.com/MediaArea/MediaInfoLib/issues/2613>
  (reporter Alexander A. Shvedov / sigdevel), closed, fixed by PR #2618.
- Pinned vulnerable source: MediaInfoLib `v26.05` commit
  `f23e69ce89581343f3b7a42e06828a5331e290d5` and ZenLib HEAD at fetch time
  `be7f11642c33094ce02cfa5ae077afdaf603a14c`, both cloned 2026-11-24 from
  GitHub into `MediaInfoLib/` and `ZenLib/` (gitignored bulk). The pinned
  `Source/MediaInfo/Audio/File_Vorbis.cpp` has the two bare early `return`s
  from `Setup()`; `ZenLib/Source/ZenLib/BitStream_LE.h` has the stale `ptr`
  read.
- Public PoC: `res/mediainfo/10/mediainfo_10` from sigdevel/pocs,
  `https://raw.githubusercontent.com/sigdevel/pocs/main/res/mediainfo/10/mediainfo_10`,
  1248 bytes, SHA-256
  `af23be76c3c0e9b9d22bc2c5d7e997fd0c44e81b277f485d6414a0bb2a277b70`.
- Fix patch: `https://github.com/MediaArea/MediaInfoLib/pull/2618.patch`,
  `fix-2618.patch`, SHA-256
  `c4ec046b9f5ce646266fa43320e8a201e0dd65f69de9466e6e703d606da36516`;
  three commits `6bacf12f` (`BS_End_LE()` before both early returns),
  `cdcd8908` (file-size display), `2a13d1b9`
  (`BT->Attach(NULL, 0)` in `Buffer_Clear()` and `Data_Manage()`).
- Build: CMake+Ninja in `build-asan/`, CMAKE_BUILD_TYPE=Debug,
  `-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1`,
  `-DBUILD_ZENLIB=ON -DBUILD_SHARED_LIBS=OFF`; harness `harness.cpp` uses the
  real `MediaInfoLib::MediaInfo::Open(path)` API, no synthetic consumer.
- All fetches were read-only provisioning; no external target was probed.
