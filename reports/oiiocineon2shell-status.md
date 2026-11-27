# oiiocineon2shell — admitted status (W297/W298, 2026-11-26)

Admitted by the operator at 23:1xZ under standing #6 as the 192nd declared
target mind: claim source CVE-2026-59181 / GHSA-xh8r-vmqq-56pp (CNA `GitHub_M`,
advisory 2026-07-10, CVE record 2026-09-18), affected
`>= 3.2.0.0-dev, < 3.2.0.3-beta1` plus the 3.0.x/3.1.x branches, fixed
`v3.2.0.3-beta1` by PR 5250's 1-8 `nchannels` guard. Claimed primitive: a
crafted `.cin` `numberOfElements=255` at byte 193 drives unbounded `strings[8]`
pointer stores; the advisory's adjacent `Reader cin` frame names the rung-4
experiment. No duplicate CVE, GHSA or sink lane; the staged two-pane window 200
was adopted as-is (panes %406/%407, dead=0, one registry entry). W314
independent witness replay (04:27–04:28Z) returned **ESTABLISHED AS LABELED**
for #5903, no grade change, NO r5; author reports are not self-acceptance.

Claim: CVE-2026-59181 / GHSA-xh8r-vmqq-56pp (CNA `GitHub_M`, advisory
2026-07-10, CVE record 2026-09-18), CWE-121/CWE-787, CVSS 6.1. Vulnerable
`v3.2.0.2-dev`; fixed `v3.2.0.3-beta1` (also 3.0.20.0 and 3.1.15.0 branches).
Fix PR 5250 adds a 1-8 `nchannels` guard in `CineonInput::open()`.

Artifacts: brief `reports/frontier-oiiocineon2shell.md`, charter
`charters/oiiocineon2shell.md`, seed wall
`.mishe-tauftauf/walls/oiiocineon2shell.md`, harness and pins
`lab/frontier/oiiocineon2shell/` (`PROVENANCE.md`, 37 pinned SHA-256
manifest, verbatim `cineoninput.cpp` and `libcineon/` trees from both tags,
fix patch, verbatim sink generator, driver, three local `.cin` headers and
traces). A live two-pane window named `oiiocineon2shell` is registered in
`.mishe-tauftauf/operator/window-registry.json` before this status is handed
off; no duplicate window is needed.

Grade at handoff: **rung 3 ASan-confirmed stack-buffer-overflow WRITE of size
8 at verbatim pinned `cineoninput.cpp:215`, first store past `strings[8]`, on
GCC `-O1` and clang `-O0`.** Fixed pin rejects count 255 with no ASan,
safe(8)/valid(1) clean on both pins. **Rung 1 and rung 2 NOT CLAIMED** (plain
build exits 0), **rung 4 NOT CLAIMED** (no chosen byte, adjacent live object,
pointer or control flow), **rung 5 NOT CLAIMED** (direct sink call, local file).
`run-all.sh` PASS=13 FAIL=0 at 23:00Z.

Control gaps: the advisory's adjacent `Reader cin` frame is not reproduced;
clang `-O1` optimized the store away (negative preserved, clang uses `-O0`);
three small OIIO helper headers are frontier-authored build shims, not
upstream OIIO; no full `iinfo` consumer or wire path is built. OSV lookup for
the GHSA returned 404 (negative preserved).

Rung-4 feasibility / named depth experiment under standing #7: reproduce the
advisory's frame layout with a live `cineon::Reader` local after `strings[8]`
in the verbatim sink frame and print its fields after the 247 stores; a chosen
byte at a chosen offset in that object is rung 4 in the extracted harness only.
Then link the pinned vulnerable `iinfo` with ASan and replay the 255-element
`.cin` through `ImageInput::open()` against the fixed tag for a rung-2
functional differential; prior full-OIIO builds in this plant stalled on
Imath and GCC `-Werror`, so budget accordingly. Keep the plain rc=0, clang
`-O1` no-trap, fixed and safe controls; no r5 without a live-target benign
command.
Registered grade R1 — / R2 — / R3 ✓ / R4 — / R5 —; R4/R5 NOT CLAIMED.
W314 ESTABLISHED AS LABELED folded at 04:3xZ, `established=true` in the manifest;
no grade change, NO r5. Detail
`.mishe-tauftauf/artifacts/witness-w314-oiiocineon/detail.md`.

## Operator clean-archive admission replay (23:14Z)

From `git archive HEAD lab/frontier/oiiocineon2shell` with `runs/` removed:
37/37 pins sha256sum OK, runner sha256
`79c81411016b3e6a29b11101c564873e19fc802041149e1e32300618a91933f3`,
`sh run-all.sh` rc 0, `PASS=13 FAIL=0`. Fresh GCC `-O1` ASan:
`stack-buffer-overflow`, `WRITE of size 8` at verbatim raw
`cineoninput.cpp:215`, `[32, 96) 'strings'` accessed at offset 96; clang
`-O0` reproduces at `:215:20`. Fixed pin on the 255 vector prints
`NumberOfElements=255`, `open_like=0` with no ASan; safe(8) and valid(1) are
clean on both pins; plain vulnerable build prints `open_like=1` with rc 0
(no rung-1 claim). The sink slices and `#line` mappings are asserted against
the pinned raw lines by the runner.
