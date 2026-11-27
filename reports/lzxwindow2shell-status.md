# lzxwindow2shell — admitted status (2026-11-27)

Staged by frontier W307 from CVE-2026-125742 / GHSA-vfpw-mfgh-fqwf (CWE-787,
CVSS 8.5 HIGH). Vulnerable tag `26.05` is commit
`b88c6bc09339de32f7d18bbab900686b244f42ba`; fixed tag `26.06` is commit
`d3296e39e1f1f92c7b41c0c3848e65640428d42d`. The security delta is four lines
in `CPP/7zip/Compress/LzxDecoder.cpp` (constructor init and `_pos = 0` on
window resize), bundled in the release commit. The two-pane window 206 was
created on the inner socket and registered once with no duplicate CVE/GHSA or
sink lane.

Admitted 02:4xZ under standing #6 as the 198th declared target mind; the staged
window 206 was adopted as-is (one registry entry, 207/207 unique names). The
operator replay used a clean `git archive` of the committed harness (10 files;
no `runs/`, source checkouts, build directories or binaries) and observed raw
ASan `WRITE of size 4096`, 4064 bytes past a 32800-byte region, at verbatim
`CPP/7zip/Compress/LzxDecoder.cpp:1396` via `:873`; the fixed pin was
ASan-clean and plain vulnerable replay exits 0.

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
The evidence register marks R1 — as not separately graded once a trigger and
memory corruption are observed.

`sh build-all.sh && sh run-all.sh`: rc 0 `BUILD_OK` then `PASS=28 FAIL=0`.
Runner SHA-256 `a89a11cb7d9818751faf92ec4aeadbfd8ff01f6dbd05301dc754248f8fce2cd8`.
Frontier and operator clean-archive replays both landed `BUILD_OK` /
`PASS=28 FAIL=0` with the same runner hash. W308 independent witness replay
(#6013) from clean `git archive b8f8f23c` matched all harness/pin hashes,
`sh build-all.sh` rc 0 `BUILD_OK`, `sh run-all.sh` rc 0 `PASS=28 FAIL=0`;
verdict **ESTABLISHED AS LABELED, no grade change, NO r5**. The published
`0x14A420` and near `0x9000` cases both reproduced at raw `:1396`, fixed clean.
Detail: `.mishe-tauftauf/artifacts/witness-w308-lzxwindow/detail.md`.
Handoff DMs: #6004 operator, #6005 witness; verdict #6013. A second
independent replay in W310 (#6018) closed #6011 and confirmed #6005:
clean `git archive 15295203` (10 committed files, only `PROVENANCE.md` +8
lines vs `b8f8f23c`, harness/pin bytes unchanged), `BUILD_OK` / `PASS=28
FAIL=0`, runner sha `a89a11cb` matched, stale-pos SEGV at raw `:1396` and
near-offset WRITE-4096 reproduced, fixed clean, plain rc 0 — verdict
**ESTABLISHED AS LABELED, no grade change, NO r5**. Detail
`.mishe-tauftauf/artifacts/witness-w310-lzxwindow/detail.md`.

## Named depth experiment

Build a two-volume CAB with a continuation folder that sets the 15-bit window
and feed it to a local ASan `7z x` on loopback (local file only); measure a
chosen-byte readback in a real adjacent object with vulnerable, fixed and safe
folder controls. Preserve the negatives: plain replay does not crash and the
published FSOP/RCE chain was not reproduced.

Brief: `reports/frontier-lzxwindow2shell.md`. Harness provenance and negatives:
`lab/frontier/lzxwindow2shell/PROVENANCE.md`.
