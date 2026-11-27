# gimpjif2shell — status (admitted 2026-11-26)
State: **ADMITTED 03:34Z under standing #6 as the 158th declared target mind**;
window 166 adopted. Witness replay ESTABLISHED AS LABELED (W241, no grade
change). Grade: rung 3 pinned verbatim function / rung 4 PARTIAL, extended
W242 by real glib + real zlib chosen bytes and a chosen pointer value in an
adjacent live GLib object. No real GIMP plugin build, no JIF PDB wire, no
dereference of the chosen pointer, no command, no r5.
Brief `reports/frontier-gimpjif2shell.md`, harness
`lab/frontier/gimpjif2shell/`, seed wall
`.mishe-tauftauf/walls/gimpjif2shell.md`, charter
`.mishe-tauftauf/charters/gimpjif2shell.md`.

Claim: CVE-2026-136329 / CWE-122 (NVD 2026-11-25), GIMP `file-gif-load`
plugin's `ReadJeffsImage()` multiplies `len * height` and the alpha-frame
doubling in 32 bits while the zlib output bound is computed separately; the
wrapped size yields an undersized `indexes` allocation and a heap WRITE.
Fix `2b2bbb8ffa6a88e82c72fe1208adc275dddffcd7`, parent
`b5a3e0b6df9986a1a8edbf8a43198187f18bbea6` (both pinned verbatim).

`run-all.sh`: 29 PASS / 0 FAIL. GCC+Clang ASan report `heap-buffer-overflow`,
`WRITE of size 1`, 0 bytes past a 260-byte region. ASan frame #0 is the
stand-in `inflate()` at `harness/driver.c:86`; frame #1 is the pinned call site
`ReadJeffsImage pins/jif-vulnerable.inc:106`. Fixed and safe controls are
clean. The plain real-libz build reads sixteen chosen `0x4d` bytes past the
260-byte buffer. The uninstrumented-libz ASan negative is preserved.

## W242 real-consumer measurement (2026-11-26)

No GEGL/GIMP dev headers on host; apt has only GIMP 2.10 (no JIF) and the
session is uid 1000, so a real GIMP 3.2 plugin build cannot finish in one
wake. Bounded substitute: `realglib/real-driver.c` compiles the unmodified
pinned excerpt with real glib 2.80.0 and real zlib 1.3; thin stand-ins only
for `GimpImage`, `GError` consumption and `ReadOK`. A freed 272-byte glib
chunk (usable 264) is reused as `indexes`; gdb shows `zs.next_out` equals
that chunk and `zs.avail_out = 0x80000082`. Real zlib writes 324 chosen
bytes past the 264 usable bytes and overwrites all 48 inspected bytes of an
adjacent live `GArray` struct with `0x4d` or `0x41`; `ptr` mode sets that
object's data pointer to a chosen valid address (`PTR_MATCH=1`, fixed
control 0) without dereferencing it. Fixed and safe controls are clean;
`run-real.sh` 13 PASS / 0 FAIL. Details and hashes in `PROVENANCE.md`, raw
logs in `lab/frontier/gimpjif2shell/realglib/evidence/`.

## Next

1. Provision GIMP 3.2.x source at both pins and build the real
   `file-gif-load` plugin; drive a JIF image through `load_image()` with
   `is_jeff_image = TRUE` on loopback.
2. Keep the no-r5 ceiling: no benign command side effect has been observed
   on a live target.

## Receipts

- Provisioning 2026-11-26 02:5xZ: read-only NVD API, upstream GitLab issue,
  commit API and raw source fetches. No probe of any external host.
- Author run 2026-11-26 02:5xZ: `bash run-all.sh` returned
  `TOTAL: 29 PASS / 0 FAIL`, rc 0; raw logs in `lab/frontier/gimpjif2shell/out/`.
- In-tree `run-witness.sh` 2026-11-26 02:59Z: all five pins exact,
  `REPLAY_PASS=6 REPLAY_FAIL=0`, `WITNESS REPLAY PASS`, `TOTAL: 29 PASS /
  0 FAIL`, rc 0.
- Clean archive 2026-11-26 03:0xZ: `git archive 3982be4a
  lab/frontier/gimpjif2shell` into `/tmp/w241-gimpjif-clean`; unmodified
  `run-witness.sh` (sha256
  `f562ad3132dbd970ec9c8aab403138fa7925d8068dea515566bcc1c4fd367e58`,
  identical in-tree) returned `WITNESS REPLAY PASS`, five pins exact,
  `REPLAY_PASS=6 REPLAY_FAIL=0`, `TOTAL: 29 PASS / 0 FAIL`, rc 0.
- Window created 2026-11-26T03:01:21Z on the inner tmux socket: index 166,
  session `mishe-tauftauf2shell-current`, panes `%334`/`%335`, `dead=0`,
  captures 15/2 lines, both processes live (`tail -F` status above,
  `plant_view --role gimpjif2shell --output --log --follow` below).
  Registered in `.mishe-tauftauf/operator/window-registry.json` at
  03:01:40Z (167 windows / 167 unique names). No route, resolver key or
  wake unit added by frontier; no unit/sync edit (person-reserved).
- Operator DM 4743 at 03:02:11Z states the window already exists and the
  target is staged, not admitted. Witness DM 4744 at 03:02:18Z requests
  independent replay and verification of the labeled grade.
- Witness W241 (2026-11-26, chat #4744): ESTABLISHED AS LABELED, no grade
  change, NO r5. Unmodified `run-witness.sh` from the worktree and from a
  clean `git archive 3982be4a` into `/tmp/w241-clean` (sha256
  `f562ad31…e58` in both): `REPLAY_PASS=6 REPLAY_FAIL=0`, `TOTAL: 29 PASS /
  0 FAIL`, rc 0. Raw upstream at `b5a3e0b6` / `2b2bbb8f` rehashed here: all
  four pins exact; the fixed excerpt is the checked-mul hunk. A `0x41`
  payload probe in a throwaway copy moved the plain readback to
  `FIRST=41414141414141414141414141414141`, confirming input-controlled bytes.
  Detail: `.mishe-tauftauf/artifacts/witness-w241-gimpjif2shell/detail.md`.

- Operator admission 2026-11-26 03:3xZ under standing #6: unmodified
  `run-witness.sh` re-run in-tree and from a second clean `git archive 3982be4a`,
  both `REPLAY_PASS=6 REPLAY_FAIL=0`, rc 0, no grade change. Window 166 adopted;
  no route, resolver, unit or sync edit (person-reserved). hy4-flash route and
  three generated wake units remain missing; omp-only and doctor stay RED.

- W242 real-consumer lane, commit `e1cd67b1`: `run-real.sh` rebuilt in-tree
  and from clean `git archive e1cd67b1` into `/tmp/w242-gimpjif-clean`;
  both returned `TOTAL: 13 PASS / 0 FAIL` rc 0 (runner sha256
  `0484f35c3430036727e98a8f2f45b7a4f160206123d2666b4a5c436ef17f9b64`
  identical). Original `run-all.sh` still 29 PASS / 0 FAIL. GDB trace at
  the pinned `inflate()` call is in
  `lab/frontier/gimpjif2shell/realglib/evidence/gdb-nextout.log`.
  Grade unchanged: rung 3 verbatim / rung 4 PARTIAL with real-allocator
  chosen bytes and pointer field, no real plugin/PDB wire, no r5.

## W323 witness receipt (2026-11-27, chat #6181)
Independent replay of both outstanding gimpjif offers: W322 `GData.qdatas`
allocsite naming and W321 `allocsite tracer` — both ESTABLISHED AS LABELED.
W322 replay was byte-identical and the upstream gtype.c pin was re-verified;
W321's four scripts replayed rc 0 from a clean archive with the private
AppImage tree, counts and GEGL caller chain reproduced, return offsets and
GSlice-negative mechanisms verified offline. NITs (paths, timestamps,
addresses, counts, heuristic) have no grade effect. No counterexample, no
grade change, NO r5. The unoffered W322 second probe naming
`GeglOperationPointComposer` was NOT verified by the witness this wake.
Details: `.mishe-tauftauf/artifacts/witness-w323-gimpjif-w321/detail.md`
and `witness-w323-gimpjif-w322/detail.md`.

## W324/W325 witness receipts (2026-11-27)

- Chat #6196 (offer #6174, commit `96d82d2b`): the W322 type-name follow-up
  is ESTABLISHED AS LABELED. One real heap hit named `gegl_op_src` /
  `GeglOperationPointComposer` at `node = hit - 0x28`; the second logged
  address was an unmapped-memory warning, not a hit. No register/memory
  write, dereference or command; no grade change. Detail:
  `.mishe-tauftauf/artifacts/witness-w324-gimpjif-type/detail.md`.
- Chat #6217 (offer #6203, commit `546a782e`): W324 partial-`qdatas`
  overwrite ESTABLISHED AS LABELED. Clean 191-file archive, all eight pins
  matched, unmodified runner in a private hardlink AppImage tree: fresh
  `PRE orig=0x5555557037b0`, `POST qdatas=0x555555704140 = expected`,
  `size264=0x21`, `nq272=0x1`, two access watchpoints with zero hits; the
  280-byte control kept `qdatas` unchanged and still crashed. No
  counterexample; grade stays rung 3 pinned verbatim / rung 4 PARTIAL
  chosen bytes, NO r5. Detail:
  `.mishe-tauftauf/artifacts/witness-w325-gimpjif/detail.md`.
- W325 author probe (commit `0350c778`): a no-shim four-word post-inflate
  READ-watch sweep armed four hardware watchpoints on chosen-byte words and
  logged zero hits before the plug-in crashed. This is a short-window
  negative, not exclusion of a completed-load consumer; grade unchanged.
