# libvnc2shell — status

Admitted 2026-11-22 ~21:2xZ under standing approval #6 as the 87th engine
route. Charter `.mishe-tauftauf/charters/libvnc2shell.md` and seed wall
`.mishe-tauftauf/walls/libvnc2shell.md` were created by frontier at W123; the
two-pane window (inner index 92, registry entry 93) already existed and was
adopted, not duplicated. Admission added the hy4-flash route and three units
from the exact full-flag sync (pin
`0d686bbad55c849e88334da64efff9da88ad528a`; `written 9, removed 0` across all
three targets). Pinned `doctor` and `check-omp-only.py` are GREEN.

- Claim: GHSA-v9pm-47h4-jcq8 / CVE-2026-50538, "Attacker-controlled heap
  out-of-bounds write in libvncclient Tight decoder", published 2026-05-29 by
  `bk138`, High, CVSS v3.1 8.8 (`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`). Source:
  `lab/frontier/libvnc2shell/harness/PROVENANCE.md`.
- Primitive: a malicious or mitm server sends one `FramebufferUpdate` with a
  legal 16x16 Tight rectangle whose zlib stream decompresses to more rows than
  the declared `rh`. `HandleTightBPP()` derives `numRows` from the decompressed
  byte count and calls `filterFn()` before the post-loop `rowsProcessed != rh`
  check, so `FilterCopyBPP()` writes rows past the framebuffer. The fix adds a
  pre-write clamp inside the loop (`if (numRows > rh - rowsProcessed) return
  FALSE`). Affected 0.9.12 through master `5ea5fc30`, introduced by `d7b1462`.
- Pins: vulnerable `73352b9de9c0`, fixed merge `540332be3e0acc566fa64da6f1b4680c72c724dd`
  (parent of the vulnerable pin; the two `tight.c` files differ by only the
  10-line clamp). **Discrepancy recorded, not corrected:** the advisory says
  "Patched versions: None" because no release tag carries the fix. Digests in
  `src/PIN_HASHES.txt` and `harness/PROVENANCE.md`.
- Evidence (`bash lab/frontier/libvnc2shell/harness/run.sh`, 20 PASS / 0 FAIL
  twice with gcc 13.3.0 and clang 18.1.3, byte-identical normalized hashes,
  plus a clean `git archive 0d4103f` replay): `gen_fn.py` extracts 275 verbatim
  lines from each pinned `tight.c` and the harness uses real zlib with no
  socket, client or server. Vulnerable pin with 32 decompressed rows into a
  16-row (1024-byte) framebuffer gives ASan `heap-buffer-overflow`,
  `WRITE of size 64`, 0 bytes after the region, frames
  `FilterCopy32` → `HandleTight32` → driver. Plain build reads back chosen
  `414243…50` at offset 1024 with base `0x41` and `5a5b…69` with `0x5a`. Fixed
  pin logs `Tight: too many scan lines after decompression.` and returns before
  `filterFn`; the 16-row safe control is clean on both pins. The advisory's
  `cutZeros` RGB24 branch reports `WRITE of size 4`; this harness uses the
  `cutZeros=FALSE` plain-memcpy branch (`WRITE of size 64`) — same loop, same
  missing clamp, recorded as distinct.
- Grade: rung 1/2 and rung 3 (ASan-confirmed heap corruption in verbatim pinned
  code) plus scoped rung 4 chosen bytes at a chosen offset at direct-call/stub
  scope. Ceiling: the victim is a **connecting VNC client**, attacker is the
  server or a mitm, `UI:R`. No live client, RFB wire, malicious server,
  `FramebufferUpdate`, callback-pointer overwrite, pointer control, marker,
  command or rung 5. The advisory's control-flow-hijack demonstration depends
  on an application whose framebuffer sits next to a callback pointer and on
  an information leak for ASLR; neither was reproduced.
- Cheapest next experiments: replay the advisory's loopback `evil_server.py` +
  ASan shape to move to wire scope; measure framebuffer-to-callback adjacency
  in the shipped SDL example; only then consider a benign marker redirect
  without an external leak. Rung 5 stays additive and per-build.
- Full stage: `reports/frontier-libvnc2shell.md`.

No witness replay has been requested yet.
