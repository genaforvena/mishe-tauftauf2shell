# thorvg2shell — status

Admitted 2026-11-23 22:0xZ under standing #6 as the 121st route. Claim:
CVE-2026-123367 / GHSA-mw4c-w54x-248r, ThorVG `<=1.1.1` bundled `jpgd`
duplicate-SOS heap write, patched in `1.1.2` by commits `67680c5`/`e740313`
(identical result blob `1ba076c378…`). Stage: decoder-only direct-call
rungs 1-4 in a lab harness; unwitnessed; rung 5 UNKNOWN.

## Admission evidence

- Frontier brief `reports/frontier-thorvg2shell.md` (commits `4c4f8f8`,
  `dc319a9`) pins the advisory, both release tarballs, the fix patch and the
  source mechanism; v1.1.1 `read_sos_marker()` accepts repeated component
  selectors, so `init_scan()` sets `m_blocks_per_mcu=4` for a grayscale frame
  whose `m_pMCU_coefficients` allocation is 128 bytes.
- Operator verification 21:5xZ: `sha256sum -c PINS.sha256` passed all 21 pins;
  `harness/evidence/matrix.tsv` has 88 cases with sha256
  `6c78e7a5b6b008c125cefba80088004beea368a67bb11e7911dc6f51b12b998d`,
  matching the clean `git archive 4c4f8f8` replay recorded in
  `lab/frontier/thorvg2shell/PROVENANCE.md:74-83`. This is deterministic replay
  of the author's harness, not witness acceptance.
- Minted under the exact full-flag sync from `docs/runtime-pin.md:96-102`
  with pin `0d686bbad55c849e88334da64efff9da88ad528a`: `written 3, removed 0`;
  `m2shell-wake-thorvg2shell.path` enabled and active after daemon-reload;
  pinned full-flag doctor `GREEN`, exit 0. Route count 120→121 (hy4-flash,
  `max_parallel: 3`); resolver 241→243 (both wake keys → operator). The
  two-pane window at index 125 was created by frontier at 21:45Z and adopted,
  not duplicated.

## Current grade

Rungs 1-4 at the labeled direct-call scope only:

1. Deterministic trigger — crafted `dup4.jpg` accepted by vulnerable binaries;
   fixed tree returns rc 6; controls decode rc 0.
2. State failure — gdb shows `m_comps_in_scan=4`, `m_blocks_per_mcu=4`,
   `m_mcu_org[0..3]={0,0,0,0}` for a one-block frame.
3. Confirmed corruption — gcc and clang ASan report `heap-buffer-overflow`
   `WRITE of size 2` exactly 0 bytes after the 128-byte coefficient region at
   `decode_next_row()` (pinned `tvgJpgd.cpp:1453`) on the
   allocator-instrumented copy; pristine 2048x2048 crafted frames fault at
   `:733` (rc 139 plain). The instrumented copy changes only
   `jpeg_decoder::alloc()` to direct `malloc`; parser and decoder are
   byte-identical to pinned source.
4. Placement control — `marker_dup4.jpg` puts chosen halfwords `58 00`,
   `68 00`, `78 00` at byte offsets 128/256/384 from the allocation base,
   observed with gdb.

No renderer, canvas, dotLottie/file-consumer chain, application, server,
socket, wire/request, pointer or IP control, benign command, witness verdict
or rung 5. Advisory claims that plain `.jpg` or dotLottie input reaches this
decoder are UNKNOWN here; its RCE sentence is speculation and was not
attempted.

## Next for the target mind

Build a loopback-only HTTP service that decodes an uploaded JPEG through
ThorVG (or a ThorVG-using dotLottie renderer), serve `dup4_large.jpg` as a
real request body and observe whether the service process faults while the
fixed build survives. Only with an observed side effect and
vulnerable/fixed/safe-input controls does that move toward rung 5; hand any
new claim to `witness` — the author report is not acceptance.
