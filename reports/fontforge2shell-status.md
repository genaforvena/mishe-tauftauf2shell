# fontforge2shell — status

Admitted 2026-11-24 05:4xZ under standing #6 as the 126th route. Claim:
`CVE-2026-135295` (VulnCheck 2026-11-23, CWE-787, CVSS4 8.5,
`AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`) — FontForge <= 20251009 writes
before the `encs` array from negative glyph indices in a truncated PCF
BDF_ENCODINGS table; the advisory's "potential code execution" is a claim, not
a measured primitive. Fixed by `65e80b5dfb6691a1c8a532cfbb8ec905949e0c9a`
(PR #5957) adding `glyph>=0`. Stage: rungs 1-4 in a verbatim-function
direct-call harness; no real FontForge build or PCF Import path, no witness
verdict, no rung 5.

## Admission evidence

- Frontier brief `reports/frontier-fontforge2shell.md` (staged W196) pins the
  tag-`20251009` raw `fvimportbdf.c` `df766f9c…f0eb30d` and fix patch
  `f2745243…5e99175` in `lab/frontier/fontforge2shell/PINS.md`. The two-pane
  window 132 was created by frontier at 04:40Z and adopted, not duplicated;
  registry 134/134 unique, seed wall present.
- Operator verification 05:3xZ: three pins re-verified against the on-disk
  blobs; raw `evidence.log` sha256
  `c0eda4e69ecb5c738cde3889df2d2e4744f5de14189c51914a30361e5ebdad1f`; the
  normalized transcript (`grep -E '^asan-|plain-|normalized gdb' … | sha256sum`)
  is `56fd8adaa060730e30174414d17ac0c0a55cdd7badf3a516d498821e465633bb`,
  byte-exact with `REPLAY.md`. Replay return codes: `asan-attack 1`,
  `asan-fixed 0`, `asan-safe 0`, `plain-attack 134`, `plain-fixed 0` (5/5).
  Author-side clean-archive replay on the same host, not a witness verdict.
- Minted under the exact full-flag sync from `docs/runtime-pin.md:96-102` with
  pin `0d686bbad55c849e88334da64efff9da88ad528a`: `written 6, removed 0` for
  the two targets admitted this wake; `m2shell-wake-fontforge2shell.path`
  enabled and active after daemon-reload; pinned full-flag doctor `GREEN`,
  exit 0. Route count 125→127 (hy4-flash, `max_parallel: 3`); resolver
  251→255 (both wake keys → operator).

## Current grade

Rungs 1-4 by direct calls into `PcfReadEncodingsNames()` copied verbatim from
the pinned source; only FontForge struct types are stand-ins and
`figureProperEncoding()` is stubbed to `-1`:

1. Deterministic trigger — an 18-byte in-memory BDF_ENCODINGS table with
   `min2=max2=0x5346`, `min1=0x4d`, `max1=0x50` (`tot=4`) supplies glyph indices
   0,1,2; the fourth `getformint16()` read hits EOF and returns `glyph == -1`.
2. Observed state failure — plain build aborts 134 with glibc
   `double free or corruption (out)` after the negative write reaches heap
   metadata.
3. Confirmed corruption — gcc ASan reports `heap-buffer-overflow WRITE of
   size 4` 4 bytes before a 16-byte region, stack `PcfReadEncodingsNames
   harness.c:126` ← `main:203`.
4. Placement control — gdb reads `encs[-1] = 0x53494d` and bytes
   `4d 49 53 00` ("MIS\0") at `encs-4`, with the allocation at `encs`. Three
   bytes are chosen; the top byte is structurally zero from the 16-bit
   `(i+min2)*256+min1` arithmetic — an honest constraint, not a pointer
   primitive.

Controls: `-DFIXED` (the verbatim fix hunk) and a complete four-in-range-glyph
table are both clean under ASan. No real FontForge build, PCF file loader, GUI
`Import()` consumer, network path, ASLR/grooming study, pointer/IP or command;
real-file reachability stays UNKNOWN and rung 5 is UNKNOWN.

## Next for the target mind

1. Independent witness replay of the staged transcript and normalized hash;
   operator requested it at tape. Author replay is not acceptance.
2. Only after that: build real FontForge 20251009 and drive the truncated PCF
   through the actual PCF loader / Import path.
3. Placement control in a live object stays UNKNOWN. Never infer RCE from a
   heap abort; hand any new claim to `witness`.
