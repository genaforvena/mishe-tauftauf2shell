# libtiffpixarlog2shell — status (ADMITTED 2026-11-26 21:0xZ, 187th target)

STAGED by frontier W287 (commit `ac20ec32`); brief
`reports/frontier-libtiffpixarlog2shell.md`, charter
`charters/libtiffpixarlog2shell.md`, seed wall
`.mishe-tauftauf/walls/libtiffpixarlog2shell.md`, harness
`lab/frontier/libtiffpixarlog2shell/` (`PROVENANCE.md` has pins, traces and
preserved negatives). ADMITTED under standing #6 at 21:0xZ after operator
clean-archive replay; two-pane window 196 adopted as-is (panes %396/%397
live, dead=0) with a unique registry entry. Independent witness replay is
owed (DM #5812); register grade unchanged at rung 3.

## Claim and pins

- CVE-2026-12912 / GHSA-cg4c-j43f-qcg7, Red Hat CNA, High 7.3
  `CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H`, CWE-122, fixed in libtiff
  4.7.2. Fix commit `ba2b04b114c5dd945107ccc613cedfcca3af73bb` adds a
  `width * 4` output-buffer guard and changes the ABGR stride-3 pointer
  advance from `llen` to `imagewidth * 4` in `libtiff/tif_pixarlog.c`.
- Pinned `tiff-4.7.1.tar.gz` SHA-256
  `f698d94f3103da8ca7438d84e0344e453fe0ba3b7486e04c5bf7a9a3fabe9b69`;
  `tiff-4.7.2.tar.gz` SHA-256
  `672bd7d10aee4606171afb864f3570b83340f6a33e2c186dc0512f7145ffdf6a`.
  Both built with
  `CFLAGS='-fsanitize=address -g -O0' LDFLAGS='-fsanitize=address' ./configure --disable-shared && make -j4`.

## Observed

- Vulnerable 4.7.1, self-contained API harness (`harness.c`), 64x1 TIFF with
  `SamplesPerPixel=3`, `COMPRESSION_PIXARLOG`, decode-side
  `PIXARLOGDATAFMT_8BITABGR`: `TIFFScanlineSize()=192` but the decoder emits
  256 bytes, a deterministic 64-byte overwrite. GCC ASan reports
  `heap-buffer-overflow`, `WRITE of size 1`,
  `0 bytes after 192-byte region`, sink
  `horizontalAccumulate8abgr` at verbatim
  `src/tiff-4.7.1/libtiff/tif_pixarlog.c:470`, caller `PixarLogDecode` at
  :979 (`op += llen` at :981), `TIFFReadScanline` at `tif_read.c:465`,
  `harness.c:124`; allocation stack `harness.c:115`. Process rc 1.
  `runs/attack-471.log`.
- Fixed 4.7.2 with the same input: rc 0, `TIFFReadScanline` returns -1 and
  logs `PixarLogDecode: Output buffer too small for PixarLog ABGR data.`;
  no ASan report. `runs/fixed-472.log`.
- Safe controls on the vulnerable build (SPP=3 with `8BITABGR` replaced by
  `8BIT`, and SPP=4 with `8BITABGR`): rc 0, successful decode, no ASan.
  Safe RGB control on 4.7.2 also clean.
- `bash lab/frontier/libtiffpixarlog2shell/run-all.sh` at 20:53Z:
  `RESULT PASS=26 FAIL=0`, `sha256sum -c pins/PIN_HASHES.txt` passed.
- Operator clean-archive replay at 21:04Z from `git archive HEAD
  lab/frontier/libtiffpixarlog2shell`, with both pinned source trees forced to
  rebuild: runner sha256
  `95aafb2b84dd1542a13b6508e7e5dac8ab9921fc50f4651e45ee0ef0fd46dbc7`, all
  five `pins/PIN_HASHES.txt` entries OK, runner rc 0, `RESULT PASS=26 FAIL=0`
  in 28 s. The same ASan WRITE-1 at `tif_pixarlog.c:470` and clean fixed/safe
  controls were reobserved from clean bytes.

## Grade and negatives

Rung 3 ASan-confirmed heap overwrite via the shipped `TIFFReadScanline` API,
with attacker-controlled sample bytes, 64 excess bytes per row and a
fixed-version plus two safe-input controls. Rung 4 NOT CLAIMED: the chosen
bytes land in ASan poison; no plain-build adjacent live object, pointer,
command buffer or socket was observed to change at a chosen offset. Rung 5
NOT CLAIMED: the CVE base vector is local with user interaction and the
trigger needs an application that opts into `8BITABGR`; no wire path was
exercised. Negatives preserved: upstream issue #824 attachment returned HTTP
403 (self-contained harness written instead), initial link failure resolved
by adding libtiff.la dependency libs, patched-4.7.1 tree not built (4.7.2
release tarball used as the fixed control), ASan PIDs/addresses/BuildIDs vary
per run and are not asserted.

## Next action

Independent witness clean-archive replay (DM #5812) is the acceptance
authority. Lane pick #7 (DM #5813): plain-build neighbouring-allocation
experiment for rung 4 — observe whether the 64 chosen sample bytes land in a
live object at a chosen offset, then attempt a benign marker. Keep the
192/256-byte arithmetic, the fixed 4.7.2 guard and both safe-format controls.
No external target; loopback only.
