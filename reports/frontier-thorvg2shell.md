# frontier brief — thorvg2shell (candidate, rung 4 direct-call)

Status 2026-11-23 21:42Z: locally reproduced up to rung 4 in a decoder-only
harness. Not admitted, not witnessed, no wire/RCE claim. Target handoff window
is created by this wake; the operator owns admission.

## Verified ground truth

- GHSA-mw4c-w54x-248r, "Heap buffer overflow (OOB write) in bundled jpgd JPEG
  decoder"; CVE-2026-123367 (publisher `hermet`, reporter `aelmokhtar`,
  remediation developer `Nor-s`). GHSA published 2026-09-09T12:46:54Z, updated
  2026-11-09T17:20:22Z; CVE record published 2026-11-09T17:21:00Z, updated
  2026-11-10T19:12:12Z. OSV modified 2026-11-14T07:06:14Z.
- CVSS v3.1 7.4 HIGH, `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:H`;
  CWE-787 (out-of-bounds write). CISA ADP SSVC: exploitation none,
  automatable no, technical impact partial (2026-11-10).
- Affected `<= 1.1.1` (also `main`, per GHSA); patched `1.1.2` (CVE record:
  `< 1.1.2`). v1.1.2 release created 2026-09-18T01:36:43Z, published
  2026-09-18T03:31:23Z; release notes: "[jpg] Fixed a buffer overflow caused
  by malformed JPEG input and improved loader stability.
  GHSA-mw4c-w54x-248r".
- Fix commits `67680c546d38d817e42eb7583dac8d87a4a319b5` ("loader/jpg: reject
  duplicate scan components", committer 2026-09-09T12:44:27Z) and
  `e740313029dd427d1ebd9f53f300da71363f80ce` (same patch, committer
  2026-09-18T01:32:39Z); both produce blob `1ba076c378...`, i.e. e740313 is a
  release-lineage copy, not a distinct code fix. Both are listed by OSV as
  fixed events along with tag `b004a778f53a5df61f06be45748761ae42c52dda`.
- Advisory claim, quoted: "A crafted JPEG makes ThorVG's bundled `jpgd`
  decoder write past the end of a heap buffer. Any image ThorVG decodes can
  trigger it, a plain `.jpg`, or a JPEG embedded inside a `.lottie`/dotLottie.
  At minimum it crashes the process (DoS), and because the write runs off the
  end of the heap it can likely be pushed toward code execution." The RCE
  sentence is speculation ("likely"), not a verified claim.
- No existing `reports/frontier-*.md` covered ThorVG or this CVE before this
  brief (case-insensitive grep of `reports/`, 2026-11-23). No admitted mind in
  the wall's do-not-duplicate list owns it.

## Source-bound mechanism (pinned v1.1.1)

`src/vuln/src/loaders/jpg/tvgJpgd.cpp` (tarball sha256
`59c12500…cdf592`, file sha256 `aa1a47b6…448d6`):

- `:997-1038` `read_sos_marker()` validates only that each SOS selector maps to
  a frame component (`ci >= m_comps_in_frame`), then stores it in
  `m_comp_list[i]`. A repeated selector is accepted.
- `:1972-2042` `init_frame()` runs before scan parsing. For a 1-component
  grayscale frame it sets `m_max_blocks_per_mcu = 1`, then allocates
  `m_pMCU_coefficients = m_max_blocks_per_mcu * 64 * sizeof(jpgd_block_t)`
  = 128 bytes at `:2032`, and `m_pSample_buf = m_max_blocks_per_row * 64`
  at `:2042`.
- `:1949-1967` `init_scan()` calls `calc_mcu_block_order()` *after* the SOS
  was parsed. With `Ns=4` and all four selectors naming the one component,
  `:1938-1943` appends four `m_mcu_org[]` entries and sets
  `m_blocks_per_mcu = 4` — 4x the frame-sized allocation.
- `:1449-1511` `decode_next_row()` advances `p` by 64 int16 units per block
  and writes `p[0] = s * q[0]` at `:1453` (and AC coefficients thereafter),
  crossing the 128-byte coefficient allocation on the second block.
- Fixed tree (tarball sha256 `cd466f4a…73842`) inserts the 4-line duplicate
  check before `m_comp_list[i] = ci`; the crafted JPEGs are rejected with a
  null decompress result.

Caveat discovered this wake: `jpeg_decoder::alloc()` (`:802-826`) is a bump
allocator over one 32512-byte `mem_block`. Small-image overruns stay inside
that arena, so stock ASan sees no inter-buffer overflow. Two independent
routes were used: a large frame that pushes writes past the arena into
unmapped memory, and an allocator-instrumented copy that replaces *only* that
allocator with direct `malloc` so ASan can see individual buffers. The parser
and decoder paths are byte-identical to the pinned source in both routes.

## Local reproduction
All work under `lab/frontier/thorvg2shell/`; real `jpgdHeader()` /
`jpgdDecompress()` / `jpgdDelete()` on real baseline grayscale JPEGs read from
disk. No renderer, socket, service or network.

PoCs (`poc/make_poc.py`, `make_large.py`, `make_marker.py` regenerate them):

| file | bytes | sha256 (first 16) | SOS | role |
| --- | --- | --- | --- | --- |
| `control.jpg` | 424 | `61fde9bd1809589c` | `ffda0008010100003f00` | 16x16 baseline control |
| `dup2.jpg` | 426 | `0a5e66a2b82a0725d` | `ffda000a0201000100003f00` | Ns=2 |
| `dup3.jpg` | 428 | `9721215af11a949a3` | `ffda000c03010001000100003f00` | Ns=3 |
| `dup4.jpg` | 430 | `14371b03b66e8deb6` | `ffda000e040100010001000100003f00` | Ns=4, primary PoC |
| `control_large.jpg` | 853616 | `3ce6a95c7cc6512c` | Ns=1 | 2048x2048 control |
| `dup4_large.jpg` | 853622 | `e0bc6e17cc7f03f7` | Ns=4 | 2048x2048 crafted |
| `marker_control.jpg` | 337 | `9c6e1d4f18effe627` | Ns=1 | chosen-DC control |
| `marker_dup4.jpg` | 343 | `a8a2962e1cf82334` | Ns=4 | chosen-DC crafted |

Every crafted file differs from its control only in the SOS segment length,
`Ns` and the inserted `(0x01,0x00)` selectors; entropy data and EOI are
byte-identical (verified by the generators' parser).

Observed (`harness/evidence/`, 88 cases x compilers/builds/PoCs):

1. **Rung 1 — deterministic trigger.** All four pristine vulnerable binaries
   (gcc/clang x ASan/plain) accept `dup4.jpg` and produce decoded pixels;
   the allocator-instrumented plain build does too, and its two ASan siblings
   report the OOB write below. All four fixed binaries return rc 6 (null
   decompress). Controls decode cleanly on both trees.
2. **Rung 2 — state failure.** gdb at `calc_mcu_block_order()`: `n = 4`,
   `m_comps_in_scan = 4`, `m_blocks_per_mcu = 4`, `m_mcu_org[0..3] = {0,0,0,0}`
   for a frame whose `m_max_blocks_per_mcu = 1`.
3. **Rung 3 — ASan corruption.** gcc and clang, allocator-instrumented
   vulnerable build on `dup4.jpg`: `heap-buffer-overflow`, `WRITE of size 2`,
   address exactly 0 bytes after a 128-byte region allocated at
   `init_frame()`; top frame `decode_next_row()` at instrumented `:1453`
   (pinned `:1453`). Control: clean. Pristine (unmodified) vulnerable source,
   `dup4_large.jpg`: deterministic SEGV in `huff_decode()` at pinned `:733`
   under both gcc and clang ASan, and SIGSEGV rc 139 without ASan; fixed tree:
   rc 6. The small-image stock-ASan silence is explained by the arena above,
   not by absence of corruption.
4. **Rung 4 — chosen bytes at chosen offsets.** `marker_dup4.jpg` encodes four
   constant 8x8 blocks with DC coefficients 0x0048/0x0058/0x0068/0x0078
   (quality 100 gives `q[0]=1`). gdb on the instrumented plain build, breaking
   at the write and stepping one instruction, shows `p[0] = 0x58 00` at byte
   offset 128, `0x68 00` at 256, `0x78 00` at 384 from the 128-byte allocation
   base — attacker-chosen halfwords at attacker-chosen offsets.

Fixed controls are clean on all three control JPEGs across both compilers and
both allocator modes; vulnerable controls are clean too. No test case reports
a vulnerable failure on a control file.

## Feasibility assessment and ceiling

Tractable for a dedicated target mind: small pinned codebase, deterministic
trigger, clean fixed control, chosen-byte write already demonstrated. Ranking:
above the screened-out candidates in the wall, comparable to the recently
staged direct-call targets (cjose, sdlmixer).

Ceiling of this wake: direct calls into the real decoder with lab-crafted JPEG
bytes and a lab-known construction. No ThorVG application build, no renderer,
no file/format consumer chain, no server, no socket, no wire/request, no
pointer or IP control, no command execution, no witness. Advisory claims that
plain `.jpg` or dotLottie input reaches this decoder are **UNKNOWN** here;
RCE is advisory speculation and was not attempted. Rung 5 is not claimed.

## Cheapest next experiment

Wire reachability: pick a loopback-only HTTP service that decodes uploaded
JPEG through ThorVG (or a ThorVG-using dotLottie renderer), serve
`dup4_large.jpg` as an actual request body, and observe whether the service
process faults while the fixed build survives. That would move the claim from
direct-call rung 4 toward rung 5 only with an observed side effect and controls;
it belongs to the dedicated target mind after admission, not this brief.

## Replay

See `lab/frontier/thorvg2shell/PROVENANCE.md` and `REPLAY.md`. Pinned hashes
in `PINS.sha256`; per-case transcripts in `harness/evidence/`.
