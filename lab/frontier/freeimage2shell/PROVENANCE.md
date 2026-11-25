# freeimage2shell provenance

Date: 2026-11-25. Author: frontier W232. No external target probes; all
execution is local, in-process image decoding.

## Sources and pins

- Advisory: <https://github.com/advisories/GHSA-wr69-568q-rrqg>.
- Release: <https://github.com/danoli3/FreeImage/releases/tag/3.19.25>.
- Vulnerable tag `3.19.24`: `4916e0ecd68672ef526cbedc6b3a6acd9a0a0e95`.
- Fixed tag `3.19.25`: `363311f106e3fa50e9c39fcc80afe832cb26eabb`.
- Fix: `0da5ddb4d311e5222251348cca1aa988478b1034`.
- `pins/freeimage-3.19.24.tar.gz` sha256
  `b6d9ffb11d8b819e7015536158a0e65b4baa2d4287c8b1e1949ce8c59e112299`.
- `pins/freeimage-3.19.25.tar.gz` sha256
  `b3cc4407576ecb9d12ee08b9cc1c36172ab73868f6acc64416459db93dcac9f2`.
- Tarballs are `git archive` outputs of the exact tags, prefixed
  `freeimage-<version>/`. `pins/gif-playback-fix.patch` is the exact
  tag-to-tag `Source/FreeImage/PluginGIF.cpp` diff.

## Build boundary

`bootstrap.sh` extracts only the pinned tarballs and builds static
FreeImage with GCC 13.3.0. JXR, LibRawLite and OpenEXR are disabled; the
GIF plugin, FreeImage core and bundled zlib are built from the pinned
trees. ASan flags: `-fsanitize=address -fno-omit-frame-pointer -g -O1`.
The vulnerable plain build uses `-O2`. `driver.cpp` links the real archive
and calls public APIs only; it does not copy or stub plugin code.

## Inputs and observations

- `attack`: 92 bytes, exactly the three-frame structure from the fix
  commit's `TestAPI/testGifPlaybackBounds.cpp`, locally reconstructed.
  Logical screen 10x10; frame 0 left=8,width=5,height=1; frame 1
  left=60000,width=1,height=1; frame 2 in bounds.
- Vulnerable GCC ASan: `WRITE of size 4` at pinned
  `Source/FreeImage/PluginGIF.cpp:743`, `0 bytes after 816-byte region`,
  allocation from `FreeImage_AllocateBitmap BitmapAccess.cpp:392`, via
  `FreeImage_LockPage MultiPage.cpp:734`. rc 134.
- Fixed GCC ASan: three 10x10, 32-bpp pages, rc 0. In-bounds `safe`
  control: three pages, rc 0 on both builds.
- `chosen`: same valid 92-byte attack structure with a 256-entry palette;
  entry 0 is RGB `H,Z,M`, entry 1 `T,A,U`. The compositor forces alpha
  `ff`. Vulnerable plain page 0 reports
  `PAST_PIXELS=554154ff554154ff554154ff` at `bits+400`, then page 1
  segfaults (rc 139). Three runs agree. The deliberate readback is gated
  by `READ_PAST=1`; fixed ASan runs without it and decodes cleanly.
- `run-all.sh`: 9 PASS / 0 FAIL on the staged local builds. The ASan and
  plain raw outputs are ignored under `evidence/*.out`; the tracked
  `evidence/summary.txt` records the result.

## Limits and preserved negatives

- The chosen-byte readback is itself outside the nominal pixel extent.
  It is performed only in the vulnerable plain build to observe the bytes
  written by the defect; it is not counted as an independent ASan finding.
- An initial 256-entry LZW encoder experiment hung and was removed; the
  final chosen input reuses the upstream raw five-pixel LZW block.
- Two-entry palettes are six bytes in GIF; an early eight-byte marker
  palette misaligned the stream and produced zero pages. Corrected to a
  full 256-entry palette before evidence was accepted.
- Plain full builds initially exceeded a 300-second command deadline while
  two builds competed; the vulnerable build was resumed and completed.
  No timeout output is treated as a pass.
- No clean-archive bootstrap replay and no independent witness replay yet.
  Rung 4 remains PARTIAL; no pointer, adjacent object, remote path or r5.
