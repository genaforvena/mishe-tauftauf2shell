# lzxwindow2shell harness provenance (W307, 2026-11-27)

All fetches were read-only provisioning from public GitHub, GHSA, CVE, OSV and
researcher pages; no target system was contacted. All runs are local files in
`lab/frontier/lzxwindow2shell/`; no sockets or external probes.

## Pins

- Vulnerable archive: `https://github.com/ip7z/7zip/archive/refs/tags/26.05.tar.gz`
  → `pins/vuln.tar.gz`, SHA-256
  `989c658cef4c13124ed1f4ff7330a6ce5ab22cefdbbc9daae9b2c110dde9a63b`.
  Tag `26.05` is commit `b88c6bc09339de32f7d18bbab900686b244f42ba`.
- Fixed archive: `https://github.com/ip7z/7zip/archive/refs/tags/26.06.tar.gz`
  → `pins/fixed.tar.gz`, SHA-256
  `63bbf0ede83e4286ec8a2905ed732a12acc36dd4771984d870b054240ce761fa`.
  Tag `26.06` is commit `d3296e39e1f1f92c7b41c0c3848e65640428d42d`.
  Both tag commits are recorded in `pins/tags.json` from the GitHub tags API.
- Upstream bundles the fix inside the 26.06 release commit; there is no
  standalone small fix commit. `pins/fix.patch` is a frontier-generated `diff -u`
  of the two **verbatim pinned** `CPP/7zip/Compress/LzxDecoder.cpp` files
  (one file, 4 added lines, SHA-256
  `5296adfbc7f92d1936c1a3a4f03799a3c03aec4a3482e957581b6ef7d9db51ce`).
  It is not presented as an upstream patch artifact.
- Pinned decoder blobs: vulnerable
  `92844d4d58653c746439b79f146128bb8196aca1f9869e43810bffb4341fd5e6`,
  fixed `384826a8913fc80e17a6188ace7371e668cbfc250be1bb4b4b5deeef7152732e`.

## Input and harness

The public writeup (https://potion-brew.pages.dev/posts/7zip-cab-lzx-window-desync-rce/)
publishes the semantic values — 21-bit then 15-bit LZX window, stale
`_pos = 0x14A420`, continuation with keepHistory, a 462-byte CFDATA payload —
but no raw CAB bytes or archive generator. `harness.cpp` is frontier-generated:
it encodes minimal LZX *uncompressed* blocks from the pinned
`LzxDecoder.cpp:1005-1120` / `:1326-1440` bit grammar. Block size is the
decoder's `high16 | low8` 24-bit encoding, verified against the pinned reader.
No upstream source file was edited. The harness calls only public API
`Set_KeepHistory`, `Set_DictBits_and_Alloc`, `Code_WithExceedReadWrite` and
public fields; the vulnerable constructor leaves `_pos` unset, so the harness
initializes it to 0 explicitly on both pins.

`sh build-all.sh` verifies pin checksums, extracts each archive only when its
tree is absent, compiles the pinned `LzxDecoder.cpp` and `C/Alloc.c` against
`harness.cpp` in ASan and plain modes for both pins. `sh run-all.sh` regenerates
the inputs in memory, checks all hashes and fix hunks, then runs both published
and near-offset differentials. Observed 2026-11-27 W307: rc 0 `BUILD_OK`, rc 0
`PASS=28 FAIL=0`; runner SHA-256
`a89a11cb7d9818751faf92ec4aeadbfd8ff01f6dbd05301dc754248f8fce2cd8`.
Host: GCC/g++ 13.3.0 with `libasan.so.8`, glibc 2.39. No ASLR manipulation,
LD_PRELOAD, debugger-forced execution or network service was used.

## Observations

- Published geometry (`0x14A420`): both pins decode a real 1,355,296-byte
  uncompressed block in a 2 MiB window and report `pos=1352736`; after
  `Set_DictBits_and_Alloc(15)` the vulnerable pin retains `pos=1352736` while
  the fixed pin reports `pos=0`. The vulnerable replay ASan-faults at raw
  `LzxDecoder.cpp:1396` with `SEGV on unknown address 0x…14a840` (address is
  `win + stalePos`, far past the 32 KiB window); the fixed run is ASan-clean.
- Near geometry (`0x9000`): same state transition with a smaller stale offset.
  Vulnerable GCC ASan reports `heap-buffer-overflow`, `WRITE of size 4096`,
  `4064 bytes after 32800-byte region`, frame `LzxDecoder.cpp:1396` inside the
  verbatim pinned uncompressed-copy sink. Fixed pin resets `_pos`, writes at
  offset 0 in the new window, and stays ASan-clean. This is the rung-3 report.
- Fixed and vulnerable `PHASE3` return `S_FALSE` because the retained byte-mode
  cursor makes the decoder's trailing-byte accounting include the earlier
  input region; the write itself is observed at both pins. This is preserved
  as a harness-shape negative, not a rung claim.

## Negatives preserved

- No raw two-volume CAB was reconstructed; the public article supplies no
  archive generator. No 7-Zip command-line consumer was exercised.
- Plain (non-ASan) vulnerable replay at `0x9000` exits 0 — the far write lands
  in mapped heap, so no plain full-program crash. No chosen-byte readback
  through a real consumer, pointer, vtable, wire path or command was observed.
- The public writeup's FILE-vtable/FSOP chain and ASLR figures are claims from
  the article, not reproduced here. Rung 4 and rung 5 are NOT CLAIMED.
