# ntfs3g2shell — status (staged W283, admission owed)

Staged by frontier W283 at 18:4xZ. CVE-2026-42618 / GHSA-6whp-3f63-97qw,
ntfs-3g LZNT1 one-byte heap overflow. Brief
`reports/frontier-ntfs3g2shell.md`, charter `charters/ntfs3g2shell.md`, harness
`lab/frontier/ntfs3g2shell/` (PROVENANCE.md has pins, hashes and negatives).

- Pins: vulnerable tarball 2026.2.25 SHA-256
  `7754f3b32e8baf9c472459b4e9c981e3ae0f5039107cdd8d8201aed0a949008a`;
  vendor patch SHA-256 `6a53ca72ae9275cb4dca0ee4b84a61ff299cbed1225dd582d9092070a358eb3f`;
  fixed release 2026.7.7, fix commit `6aa66d98980ac1d966d7977c7b079f4fe380eb42`.
- Input: deterministic 4 MiB NTFS image; MFT record 16 has one non-resident
  compressed `$DATA` (16 clusters, one sparse run), final LZNT1 sub-block
  header `0x8b57` with two literal tokens after a full 4096-byte output.
- `sh run-all.sh`: `RESULT PASS=31 FAIL=0`; vulnerable GCC ASan
  `heap-buffer-overflow`, `WRITE of size 1` at verbatim `compress.c:568`,
  0 bytes after a 65,536-byte region allocated at `compress.c:783`, via
  the shipped CLI frames `ntfscat.c:371 -> attrib.c:1003 -> compress.c:950`.
  Vendor-patched build and safe-input control: rc 0, 65,536 bytes, ASan-clean.
- Grade: rung 3 ASan in verbatim pinned source via shipped CLI / rung 4 NOT
  CLAIMED — no chosen-offset readback, adjacent object, pointer, command,
  socket or r5. The advisory's SUID `ntfs-3g` path was not driven (mount
  refused in this lab); no plain build was run.
- Preserved negatives: upstream fix-commit patch failed 6/8 hunks on the tag;
  scout's earlier `0x9201` header exceeded `NTFS_SB_SIZE_MASK`; no public PoC
  bytes found; image bytes are locally derived.
- Owed: operator admission, witness clean-archive replay, plain-build
  chosen-object experiment. Window staged by frontier; no duplicate needed.
