# Frontier brief: oiiocineon2shell — CVE-2026-59181 (unchecked numberOfElements writes past `strings[8]`)

**Status: STAGED 2026-11-26 W297 — rung 3 ASan-confirmed stack-buffer-overflow
WRITE of size 8 at verbatim pinned `cineoninput.cpp:215`.** Rung 1 and rung 2
NOT CLAIMED (plain build exits 0); rung 4 and rung 5 NOT CLAIMED (no chosen
byte, neighbouring object, pointer or command observed). Claim sources are
attributed below; pinned bytes and observations are this plant's own. The
witness re-runs any published claim; the operator owns admission under
standing #6. Frontier owns no further work after handoff.

## Verified ground truth (claim sources read 2026-11-26)

- **Claim sources:** GHSA advisory
  https://github.com/AcademySoftwareFoundation/OpenImageIO/security/advisories/GHSA-xh8r-vmqq-56pp
  (`lgritz`, published 2026-07-10) and canonical CVE record
  https://cveawg.mitre.org/api/cve/CVE-2026-59181 (CNA `GitHub_M`, published
  2026-09-18). Fix PR https://github.com/AcademySoftwareFoundation/OpenImageIO/pull/5250.
  OSV lookup for the GHSA returned 404; that negative is preserved.
- **Versions:** vulnerable tag `v3.2.0.2-dev`; CVE affected ranges `< 3.0.20.0`,
  `>= 3.1.0.0, < 3.1.15.0`, `>= 3.2.0.0-dev, < 3.2.0.3-beta1`; fixed tag
  `v3.2.0.3-beta1` (GHSA says `>= 3.2.0.3`). Advisory version strings and the
  upstream tag spelling differ; the pins below are authoritative for this lab.
- **Claimed primitive:** CWE-121/CWE-787, CVSS 6.1 (`AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H`).
  A crafted `.cin` supplies `numberOfElements` (documented 1-8) as 255;
  `CineonInput::open()` uses it as the loop bound filling `char* strings[8]`,
  writing pointers beyond the stack array into adjacent state. The advisory
  reports a focused ASan harness with `WRITE of size 8` and an adjacent
  `Reader cin` object; a full `iinfo evil.cin` build is claimed to reproduce.
  No web-facing consumer, confidentiality breach or remote execution is claimed
  by the advisory.
- **Fix mechanism (source-bound):** PR 5250 adds
  `int nchannels = m_cin.header.NumberOfElements(); if (nchannels < 1 || nchannels > 8) { errorfmt(...); close(); return false; }`
  in `CineonInput::open()` (pinned fixed raw lines 96-101) and uses the
  validated count in the subsequent metadata loops. The sink loop still exists
  at fixed raw lines 251-252, so the guard, not loop deletion, is the control.

## Source-bound mechanism (pinned bytes)

`pins/vuln/cineoninput.cpp` is the verbatim upstream blob at `v3.2.0.2-dev`
(git blob `d64ac4ab3d67db003c70f04f8faaace3ada66356`, SHA-256
`8e1b22819400e068963d56d60f2b6b5506376a28af189359a62fa6048f34a2a6`):
raw `:209` declares `char* strings[8]`, `:214` loops over
`m_cin.header.NumberOfElements()`, and `:215` stores
`strings[i] = get_descriptor_string(...)` with no upper bound. The fixed pin
(git blob `6174e91630067d36562944144bf7dff2b62ac736`) adds the guard at
`:96-101`. `gen_sink.py` copies these raw lines verbatim into sink translation
units with `#line` mappings; `run-all.sh` asserts the slices and mappings.

The value is read from a real 2048-byte `.cin` file: `gen.py` sets the magic
cookie at offset 0 and `numberOfElements` at offset 193, matching the advisory
generator. Upstream `InStream::Open`, `Reader::SetInStream` and
`Reader::ReadHeader` (verbatim pinned libcineon) parse the header before the
pinned sink slice runs. Only three local `.cin` files are used: 255 (attack),
8 (boundary) and 1 (valid).

## Local observation (2026-11-26 W297, GCC and clang ASan)

`run-all.sh` verifies all 37 pin hashes, regenerates sinks and headers, builds
GCC ASan vulnerable/fixed, plain vulnerable and clang `-O0` ASan vulnerable,
then runs each vector. Result at 23:00Z: **PASS=13 FAIL=0**.

- GCC ASan, 255-element file: `ERROR: AddressSanitizer:
  stack-buffer-overflow`, `WRITE of size 8` at
  `src/cineon.imageio/cineoninput.cpp:215` in `open_like`, described as
  `[32, 96) 'strings' <== Memory access at offset 96 overflows this variable`
  — the first store past the eight-element array. `runs/asan-vuln-attack.out`.
- clang 18 at `-O0` reproduces `WRITE of size 8` at raw `:215:20`
  (`runs/clang-asan-vuln-attack.out`).
- Fixed pin on the same 255 file prints `NumberOfElements=255`, `open_like=0`,
  exits 0 with no ASan report; safe(8) and valid(1) are clean on both pins.
- Plain vulnerable build exits 0 on the 255 file. Negative preserved: no
  rung-1 crash or rung-2 state failure in this harness.
- clang 18 at `-O1` optimized the out-of-bounds store away (`rc=0`, no ASan).
  This is a preserved negative; the runner uses `-O0` for clang and GCC at
  `-O1` still reports. It is not presented as a second independent compiler
  confirmation at the same optimization level.

Build scope: only the six upstream `libcineon` `.cpp` files from the advisory
recipe are compiled. Three frontier-authored headers under `h/shim/OpenImageIO/`
supply the OIIO helpers those files include (`safe_strcpy`, `fmt::format`,
`stoi`, `Filesystem::fopen`, `Sysutil::get_local_time`); they are not part of
the sink. No full OIIO build is claimed. Full details:
`lab/frontier/oiiocineon2shell/PROVENANCE.md`.

## Rung-4 feasibility (honest)

- **Rung 1 and rung 2 NOT CLAIMED.** The plain harness exits 0; there is no
  observed crash or corrupted accounting outside ASan.
- **Rung 3 ASan confirmed** at the verbatim pinned store with GCC `-O1` and
  clang `-O0`; fixed and safe controls clean.
- **Rung 4 NOT CLAIMED.** The harness has no adjacent live consumer object in
  the sink frame (the advisory's `Reader cin` frame is not reproduced), no
  chosen value is read back, and the stored pointer is a constant string.
  Nothing here demonstrates control of neighbouring bytes, a pointer or
  execution. The advisory's "adjacent state" description remains a claim.
- **Rung 5 NOT CLAIMED.** No `iinfo` binary, file-upload path, network service,
  wire input or remote command was exercised.

## Cheapest local experiment that could move this up a rung

1. Reproduce the advisory's exact frame layout: keep a live `cineon::Reader`
   local after `strings[8]` in the same function and print its fields after
   the 247 stores (rung 4 only if chosen bytes at chosen offsets are observed
   in that object; the sink slice must remain verbatim and the fixed/safe
   controls clean).
2. Build the pinned `v3.2.0.2-dev` `iinfo` with ASan and replay the local
   255-element `.cin` through `ImageInput::open()`, comparing with
   `v3.2.0.3-beta1`; a vulnerable/fixed functional differential would move
   rung 2. Prior OIIO builds in this plant stalled on GCC `-Werror` and Imath
   dependencies, so this is hours-scale, not a quick follow-up.
3. Resolve why the plain build exits 0 (stack slack and the constant stored
   pointer) before claiming crash reachability. Never relabel an ASan WRITE
   or a local file parse as remote command execution.

## Ranking note (W297)

Three read-only scouts covered OpenImageIO, VVdeC and fresh November 2026
advisories. OpenImageIO's Cineon sink is the most tractable candidate: a
standalone upstream parser harness needs no OIIO library, no full decoder and
no network. VVdeC CVE-2026-124309 has a published bitstream but needs a full
decoder build; VVdeC GHSA-w829-5g45-5g7q needs a full `PelStorage` context.
sngrep CVE-2026-121943 (tractability 5) remains a fresh backup; no report,
charter, wall, lab directory or window for this slug existed before this
wake, and it is not in the frontier do-not-duplicate list. Ranked by measured
local tractability, not advisory severity.
