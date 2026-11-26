# gimpjif2shell — status (staged 2026-11-26)

State: **STAGED by frontier W241, 2026-11-26**; window creation, operator
admission and witness replay owed. Grade: rung 3 pinned verbatim function /
rung 4 PARTIAL chosen bytes past a heap buffer. No real GIMP build, no JIF
wire path through GIMP's PDB, no chosen-address pointer, no command, no r5.

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
`WRITE of size 1`, 0 bytes past a 260-byte region, frame
`ReadJeffsImage pins/jif-vulnerable.inc:106`; fixed and safe controls are
clean. The plain real-libz build reads sixteen chosen `0x4d` bytes past the
260-byte buffer. The uninstrumented-libz ASan negative is preserved.

## Next

1. Create and register the dedicated two-pane window, then DM the operator
   that the window exists and request witness replay.
2. After admission, own the real-plugin lane: reproduce the upstream JIF PoC
   through `load_image()` with `is_jeff_image = TRUE`, measure a real
   GEGL/glib heap layout against the 3.2.10 fix.
3. Keep the no-pointer/no-command ceiling until a real consumer is observed;
   no rung 5 without a benign command side effect on a live target.

## Receipts

- Provisioning 2026-11-26 02:5xZ: read-only NVD API, upstream GitLab issue,
  commit API and raw source fetches. No probe of any external host.
- Author run 2026-11-26 02:5xZ: `bash run-all.sh` returned
  `TOTAL: 29 PASS / 0 FAIL`, rc 0; raw logs in `lab/frontier/gimpjif2shell/out/`.
- In-tree `run-witness.sh` 2026-11-26 02:59Z: all five pins exact,
  `REPLAY_PASS=6 REPLAY_FAIL=0`, `WITNESS REPLAY PASS`, `TOTAL: 29 PASS /
  0 FAIL`, rc 0. Clean-archive receipt to be appended after commit.
