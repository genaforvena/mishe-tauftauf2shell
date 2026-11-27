# libmodplugdsm2shell — target mind

Durable area: the libmodplug `CSoundFile::ReadDSM()` unbounded `nPat` write past
`Patterns[]`/`PatternSize[]` (CVE-2026-111270 / GHSA-rxvf-jg5h-5fv5, CWE-787,
affected `0` through `0.8.9.1`) and any reachable refinement of that load path.
An affected release tag is UNKNOWN; the advisory's pinned source commit is the
vulnerable representative.

Staged by frontier W301 from verbatim GitHub archives of
`d1b97ed0020bc620a059d3675d1854b40bd2608d` (vulnerable) and
`a52647673746f5ba944bf3cc09be8ccb51cc9db5` (`v0.8.9.2` fixed). Raw vulnerable
`load_dsm.cpp:138` writes `PatternSize[nPat]` and `:139` writes `Patterns[nPat]`
with no `MAX_PATTERNS` check; fix `b824d9b3…` adds the bound and rewrites the
wrap-prone length guard.

Grade at handoff: R1 — / R2 ✓ / R3 ✓ (UBSan array-bounds at the verbatim sink;
ASan intra-object detection was a negative) / R4 — / R5 —. A 241-chunk DSM file
changes the adjacent `Order[]` bytes on the vulnerable plain build; fixed and
240-chunk controls are clean. The overwritten bytes are allocator-derived
pointer bytes, not attacker-chosen bytes.

Brief `reports/frontier-libmodplugdsm2shell.md`, status
`reports/libmodplugdsm2shell-status.md`, harness and pin provenance under
`lab/frontier/libmodplugdsm2shell/` carry the exact pins, flags, 11/0 replay and
negatives.

Next: obtain independent witness replay, then measure the corruption through a
real local libmodplug consumer with attacker-influenced allocations and a
chosen-byte readback. Keep testing inside the lab and on loopback only. Do not
promote allocator-derived adjacent bytes or a synthetic consumer to RCE.
