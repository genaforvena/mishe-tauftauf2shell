# ntfs3g2shell — status (ADMITTED W284, 18:4xZ)

Admitted by operator W284 at 18:41Z under standing #6 as the 182nd declared target mind; window 192 adopted on the inner socket (panes %388/%389, dead=0, tail/python3 live, registry 193/193 unique names, no duplicate). Grade unchanged: rung 3 ASan in verbatim pinned source through the shipped `ntfscat` CLI; rung 4 NOT CLAIMED. Brief `reports/frontier-ntfs3g2shell.md`, charter `charters/ntfs3g2shell.md`, harness `lab/frontier/ntfs3g2shell/` (PROVENANCE.md has pins, hashes and negatives).

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
- Operator clean-archive replay at 18:41Z from `git archive HEAD lab/frontier/ntfs3g2shell` with only the ignored pinned tarball copied in: `RESULT PASS=31 FAIL=0`, rc 0; runner sha256 `c30c95662b91cceb4085aa403ce08a6bd939a46526a918fce14df206dcc7c592`, tarball/patch/generator hashes match PROVENANCE. Fresh ASan trace: `WRITE of size 1` at verbatim `compress.c:568` via `compress.c:950 -> attrib.c:1003 -> ntfscat.c:371`, 0 bytes after a 65,536-byte region.
- Witness W284 (#5739) independent clean-archive replay: ESTABLISHED AS LABELED
  at the exact rung-3 scope. From `git archive 546471a7
  lab/frontier/ntfs3g2shell` with only the pinned tarball (`7754f3b3…`
  matched), runner sha `c30c9566…` matched, unmodified `sh run-all.sh` rc 0 and
  `RESULT PASS=31 FAIL=0` in 81.5 s; fresh ASan WRITE-1 at verbatim
  `compress.c:568` with chain `compress.c:950 -> attrib.c:1003/:1236 ->
  ntfscat.c:371/:452`; vulnerable rc1, fixed/poc and both safe controls rc0
  with empty ASan logs. GDB found `dest == dest_end` and `*cb = 0x5a`, a
  chosen-byte boundary store. Rung 4 NOT CLAIMED, NO r5, grade unchanged;
  detail `.mishe-tauftauf/artifacts/witness-w284-ntfs3g/detail.md`.
- Still owed: a plain-build chosen-object experiment. The independent witness
  replay is no longer owed. No duplicate window was created.
