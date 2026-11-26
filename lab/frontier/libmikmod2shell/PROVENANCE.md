# PROVENANCE — libmikmod2shell (W276, 2026-11-26)

All fetches were public provisioning reads (GHSA/CVE/NVD/CVE.org/OSV pages,
GitHub API and codeload tarballs); no external target was probed, no socket was
opened and no audio device was touched. Everything executed was local.

## Pins and exact bytes

- Vulnerable: `08d7d2106ce3d1d6ef1dddb060e04a10b7dc8ae2`, parent of the fix.
  Fixed: `a125eabbd086f311496ae46d08aaebcad0a1c426` (one file, +7/-1, from
  `https://github.com/sezero/mikmod/commit/a125eabbd086f311496ae46d08aaebcad0a1c426`).
  Tag `libmikmod-3.3.13` = `b25f6ee25bdfc05d21b6e7f1f6a72eb15fa1ebb2`;
  tag `libmikmod-3.3.14` = `8de19eef766d9ba30a74c19e566edfcd61851dba`;
  compare fix...3.3.14: status `ahead`, ahead_by 6, behind_by 0.
- Codeload tarballs and SHA-256:
  `https://codeload.github.com/sezero/mikmod/tar.gz/08d7d2106ce3d1d6ef1dddb060e04a10b7dc8ae2`
  = `dbe73e92401f7e12d2153169b15da2f9981bc8323395d5dc2e35e08946f56f42`;
  `https://codeload.github.com/sezero/mikmod/tar.gz/a125eabbd086f311496ae46d08aaebcad0a1c426`
  = `a9d7cba3e1867fefbf385cb16da859d23e042fbe54a8ee370ced963d5e537f44`.
- Verbatim `libmikmod/loaders/load_dsm.c` SHA-256: vulnerable
  `42fa90bb7dd4fbbf8f00c3dcc39743f8848786014aead7c51d7e1ae5d8e147d5`, fixed
  `553c70854ee37041b9ff1d9d2c2bcdd17451956e6368a896f498e7a66c5836fe`.
  `diff -u` of the two files shows exactly the fix hunk quoted in the brief.
- Local files SHA-256: `harness/driver.c`
  `fd12e2f32dc80f7b5af37690ecee34c97b44b2f0b1d5f1b929f3ccb1a43429e3`,
  `harness/make_dsm.py`
  `ce529c15020f1771da6358d6382cef4eddeacf7f11705cc50c2ac5c4de9ab4cd`,
  `run-all.sh`
  `332485d16ab6d811f00e582b8b789ab21047dcc5ddfdc926e4f0c5e43a30077c`,
  `verify.sh`
  `40e841d7e4a9e76f7f0a383a84338bfe707bdd4a9aa68a7cb1bf535fcfcd1929`,
  console `evidence-run-console.log`
  `5db271f6d57e913b8d119f6b1852568ebc37b5df1f38df240872dcaac177b2a2`.

## Reproduce

Refetch the two tarballs into `src/vuln.tar.gz` and `src/fixed.tar.gz`, check
hashes above, extract if needed, then:

```
sh ./run-all.sh | tee evidence-run-console.log
sh ./verify.sh | tee -a evidence-run-console.log
```

`run-all.sh` builds each pinned library with GCC 13 CMake `-fsanitize=address
-fno-omit-frame-pointer -g -O1` and links the local driver against the pinned
static library. Only `harness/driver.c` and `harness/make_dsm.py` are local; no
upstream source is modified. The CMake `all` target also builds docs and fails
where `makeinfo` is absent; the script builds only `mikmod-static`.

## Inputs and observed bytes

- `inputs/attack.dsm` (`469d0d844fef2539db7ca2113b22d4da3f669aedbf1e675fecb5b3e17f438f53`,
  432 bytes): `numchn=2`, `numpat=32769`, product 65538 truncated to `numtrk=2`,
  one INST and two empty PATT chunks. Vulnerable pin: ASan `WRITE of size 8`
  at verbatim `load_dsm.c:339` in `DSM_Load`, 0 bytes after the 16-byte
  `AllocTracks()` region, rc 1. Fixed pin: `errno=9`, no ASan, rc 1.
- `inputs/attack16.dsm`
  (`f99bb5698fdcb6a9bb6a11dc901b91bb7b662030b34117924c155cb1884ba6a9`,
  432 bytes): `numchn=16`, `numpat=4097`, product 65552 truncated to 16;
  vulnerable ASan WRITE 0 bytes past a 128-byte region, fixed clean reject.
- `inputs/safe.dsm`
  (`0fc2ffcce73c0ce92d7e657040b3c54e16bddf80340e863be992c43f721bd475`,
  432 bytes): product 4, two PATT chunks, both pins rc 0,
  `channels=2 patterns=2 tracks=4 samples=1`, no ASan.
- Evidence: `evidence/vuln-asan-attack.out`
  (`40a77dbc7ab53330043a0a19836ef8496ff9e5d44328bcc96bc22b3d951b2288`),
  `evidence/vuln-asan-attack16.out`
  (`0345168146bf532b8df19f23dc672de0d5a19cc4a2f172df5cf91c4c2196e48a`),
  `evidence/vuln-asan-safe.out`
  (`b45085baa52065be465023d3103f6ce3dca52797bb46b0e94871765c456b43a2`),
  `evidence/fixed-asan-attack.out` and `...attack16.out` (both
  `ec7ff748f1cd7b6f3c632101c088e63a1c18a29d0b0c41e560e10b18f6e375b6`),
  `evidence/fixed-asan-safe.out` (same hash as vuln safe).
- `verify.sh`: `RESULT PASS=12 FAIL=0` at 16:14Z.

## Preserved negatives and caveats

- No public PoC bytes were found; inputs are derived from the pinned loader's
  field layout. Earlier wall estimate "~300 KB / 4097 PATT blocks" is
  unverified: these 432-byte files trigger the first OOB write on the second
  PATT chunk. The advisory's "potential code execution" is a claim, not an
  observed result.
- Only GCC ASan was run; ASan puts the overwritten pointer in poison, not a
  chosen adjacent object. No plain-build grooming, no chosen-byte readback, no
  pointer/control-flow steering, no command and no r5.
- No wire request, no file-consumer application, no network and no audio
  device; the DSM file is opened directly by the local driver. AV:L is the
  advisory's vector.
- `of.numtrk == 0` wraps are rejected by `AllocTracks()`; the small-nonzero
  wrap is the exercised case. Fixed pin rejects both attack files at the
  header with `MMERR_LOADING_HEADER` (`errno=9`).
- Advisory is unreviewed NVD import with "Unknown" package/version metadata;
  CVSS and affected range come from CVE/NVD/OSV, not a repo-published GHSA.
