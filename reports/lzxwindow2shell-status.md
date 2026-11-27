# lzxwindow2shell — staged status (2026-11-27)

Staged by frontier W307 from CVE-2026-125742 / GHSA-vfpw-mfgh-fqwf (CWE-787,
CVSS 8.5 HIGH). Vulnerable tag `26.05` is commit
`b88c6bc09339de32f7d18bbab900686b244f42ba`; fixed tag `26.06` is commit
`d3296e39e1f1f92c7b41c0c3848e65640428d42d`. The security delta is four lines
in `CPP/7zip/Compress/LzxDecoder.cpp` (constructor init and `_pos = 0` on
window resize), bundled in the release commit. The two-pane window 206 was
created on the inner socket and registered once with no duplicate CVE/GHSA or
sink lane.

The harness drives the pinned decoder through three public-API phases: decode
a real uncompressed block in a 21-bit window, shrink to 15 bits, replay a
4096-byte block through the wrapped bounds check. At the published stale
offset `0x14A420`, the vulnerable pin retains `pos=1352736` and ASan reports a
fault at raw `LzxDecoder.cpp:1396`; the fixed pin resets `pos=0` and stays
clean. At a near offset `0x9000`, vulnerable GCC ASan reports
`heap-buffer-overflow`, `WRITE of size 4096`, 4064 bytes after the 32800-byte
window allocation, frame `LzxDecoder.cpp:1396`; fixed stays clean.

Registered grade at handoff: **R1 ✓ / R2 ✓ / R3 ✓ / R4 — / R5 —**. R3 is an
invalid write in the verbatim pinned sink with generated caller input. No real
CAB consumer, chosen-byte readback, pointer, wire path, marker or command was
observed. Plain vulnerable replay exits 0; no full-program crash is claimed.

`sh build-all.sh && sh run-all.sh`: rc 0 `BUILD_OK` then `PASS=28 FAIL=0`.
Runner SHA-256 `a89a11cb7d9818751faf92ec4aeadbfd8ff01f6dbd05301dc754248f8fce2cd8`.
Clean-archive replay is owed to the witness; this author report is not
acceptance.

Brief: `reports/frontier-lzxwindow2shell.md`. Harness provenance and negatives:
`lab/frontier/lzxwindow2shell/PROVENANCE.md`.

Clean-archive replay from `git archive b8f8f23c lab/frontier/lzxwindow2shell`
(10 committed files, no `runs/` or builds) returned rc 0 `BUILD_OK` then rc 0
`PASS=28 FAIL=0` with the same runner hash. Handoff DMs: #6004 operator,
#6005 witness.
