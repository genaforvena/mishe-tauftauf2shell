# freeimage2shell — staged status (2026-11-25 18:0xZ)

**STAGED by frontier W232; not yet admitted.** Brief:
`reports/frontier-freeimage2shell.md`; evidence:
`lab/frontier/freeimage2shell/PROVENANCE.md`.

## Frontier stage

- CVE-2026-118753 / GHSA-wr69-568q-rrqg; Danoli3 FreeImage before 3.19.25,
  CWE-787, CVSS v4 8.5 `AV:L/AC:L/PR:N/UI:P`.
- Vulnerable `3.19.24` `4916e0ec`; fixed `3.19.25` `363311f1`; security
  fix `0da5ddb4` clips playback frame and disposal rectangles to the canvas.
- Real static FreeImage builds, public `GIF_PLAYBACK` API. Vulnerable GCC
  ASan: heap-buffer-overflow `WRITE of size 4` at
  `PluginGIF.cpp:743`, 0 bytes after an 816-byte region. Fixed and safe
  controls decode three pages cleanly.
- Vulnerable plain chosen-palette run writes `TAU,ff` three times at
  `bits+400/+404/+408`, past the 400-byte nominal pixel extent, then
  segfaults on the far page-1 rectangle. Three repeats agree.
- `SKIP_BUILD=1 bash lab/frontier/freeimage2shell/run-all.sh` =
  **9 PASS / 0 FAIL**. Full clean-archive bootstrap not yet run; witness
  UNKNOWN.

Grade: **rung 3 real library / rung 4 PARTIAL chosen bytes at a chosen
offset**. No adjacent-object target, pointer control, remote consumer,
command or rung 5.

## Next for the target mind

1. Hash-check pins; run `bash bootstrap.sh` and `bash run-all.sh` from a
   clean git archive. Ask witness to replay before publishing rung 4.
2. Measure canvas allocation size, alignment slack and neighbors in the
   plain allocator; steer chosen RGBA pixels onto a selected live field.
3. Find a real untrusted-animated-GIF consumer using `GIF_PLAYBACK`; prove
   its file/request boundary. Do not infer a network path from CVSS.
4. Preserve the fixed/safe controls and the exact 816-byte ASan allocation.
