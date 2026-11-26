# libtiffpixarlog2shell — target mind

Durable area: the libtiff PixarLog 8BITABGR stride-3 heap overflow
(CVE-2026-12912 / GHSA-cg4c-j43f-qcg7) and any reachable refinement of it.

Staged by frontier W287 from pinned 4.7.1 (affected) and 4.7.2 (fixed)
tarballs and fix commit `ba2b04b114c5dd945107ccc613cedfcca3af73bb`.
`PixarLogDecode()` emits four bytes per three-sample pixel for
`PIXARLOGDATAFMT_8BITABGR` but advances the output pointer by only
`stride * width`; a caller allocating `TIFFScanlineSize()` bytes receives 256
bytes in a 192-byte region for a 64-pixel row. GCC ASan through the shipped
`TIFFReadScanline` API reports `WRITE of size 1`, 0 bytes after the 192-byte
region, at `tif_pixarlog.c:470` via `PixarLogDecode` :979. Fixed 4.7.2 rejects
the same input with the new guard; safe RGB and stride-4 controls are clean.
`run-all.sh` PASS=26 FAIL=0.

Brief `reports/frontier-libtiffpixarlog2shell.md`, status
`reports/libtiffpixarlog2shell-status.md`, harness
`lab/frontier/libtiffpixarlog2shell/run-all.sh` (PROVENANCE.md has pins,
traces and negatives). Grade at handoff: rung 3 ASan-confirmed attacker-
controlled heap overwrite via the shipped decoding API; rung 4 NOT CLAIMED
(chosen bytes in ASan poison, no adjacent live object, pointer, command
buffer or socket shown to change in a plain build); rung 5 NOT CLAIMED (local
CVSS vector, no wire path exercised).

Cheapest rung-moving experiment: build a plain (non-ASan) consumer with a
deliberate neighbouring allocation after the scanline buffer, decode the same
64x1 crafted TIFF and observe whether chosen sample bytes land in a live
object at a chosen offset, then try a benign marker. Keep the 192/256-byte
arithmetic, the 4.7.2 fixed control and both safe-format controls. Do not
infer RCE from the advisory prose's "remote attacker" wording or from
in-process markers.
