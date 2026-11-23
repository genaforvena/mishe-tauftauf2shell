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

## W183 consumer and loopback-wire findings, 2026-11-23 22:53Z

New author evidence in `lab/frontier/thorvg2shell/PUBLIC_API.md`; still not a
witness verdict and still **not rung 5**. The structural UNKNOWN from admission
— does a real ThorVG consumer reach `jpgd`? — is now answered for two public
entries, using real v1.1.1 / v1.1.2 shared libraries built with `-Dloaders=jpg`:

- `tvg::Picture::load(data,size,"jpg")` on in-memory bytes (`harness/evidence/public-api.tsv`):
  8 PoCs x 2 builds; every control rc 0 with correct dimensions on both;
  `dup4_large.jpg` rc 139 on v1.1.1, rc 0 on v1.1.2. gdb
  (`public-api-gdb.txt`) places the SIGSEGV in `huff_decode()` at pinned
  `tvgJpgd.cpp:733` via `decode_next_row()` → `jpgdDecompress()` →
  `PictureImpl::load()` (`tvgPicture.h:313`).
- Plain filename API `tvg::Picture::load(path)` with `-Dfile=true`
  (`public-api-file.tsv`): identical outcome, so the advisory's plain `.jpg`
  entry reaches the fault on this host.
- Loopback-only HTTP service (`harness/loopback_server.cpp`, `wire.tsv`):
  `POST /decode` body goes straight into `Picture::load(data,size,"jpg")`.
  v1.1.1: health 200, safe 853616-byte body 200, crafted 853622-byte body
  000 with server SIGSEGV (wait rc 139). v1.1.2: 200 for all three, server
  alive. No external address was contacted; only 127.0.0.1:18081 was bound.

Grade: rung 4 is now request-reachable through a real public API and a real
loopback wire body, with vulnerable/fixed/safe-input controls. There is still
no renderer canvas, dotLottie asset, pointer or IP control, benign marker,
command, shell or rung 5. RCE remains advisory speculation. Hand carried to
`witness` for independent replay; author report is not acceptance.

## W184 crash-mechanism check, 2026-11-23 23:3xZ

Closed the control-flow-target prerequisite with a bounded gdb measurement on
the real v1.1.1 library (`harness/evidence/crash-mechanism.txt`, author
observation, not a witness verdict). At the `dup4_large.jpg` SIGSEGV the fault
is `mov 0x904(%rsi,%rdx,4),%ebp` with `rsi = pH = 0x5555555736a8` and
`rdx = 0x51586067`; `si_addr` equals `pH + 0x904 + 4*rdx` exactly. `pH` is the
decoder's own legitimate `m_pHuff_tabs[0]`, 17072 bytes beyond the overflow
base, so it is not overwritten; the forward overflow lands in `m_pSample_buf`
(pixel scratch), not a pointer, vtable or saved return address. The huge index
is a DATA value produced inside `huff_decode` when 4 blocks per MCU
desynchronise the entropy bitstream; it indexes the embedded `tree[]` array
out of bounds. No pointer or instruction-pointer control was observed.

Disposition: the charter's benign-marker lane requires an observed pointer or
control-flow target; none exists, so it is not entered. Rung 5 remains
UNKNOWN and unattempted. No witness verdict has arrived; the witness wake is
currently RED for an engine-start failure outside this target's lane.
