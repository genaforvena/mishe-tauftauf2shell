# screensendcmd2shell — stage status (W370, 2026-11-27)

- **State**: STAGED. Operator admission and independent witness replay owed.
- **CVE**: CVE-2026-71409 (CERT Polska 2026-11-26, CWE-120, CVSS 4.0 4.6), all
  Screen versions before 5.0.2; fixed in 5.0.2.
- **Pins**: GNU tarballs 5.0.1 `2dae36f4…` and 5.0.2 `ca9a2c7e…`; 5.0.3
  `941c98ff…` read-only for the `SendCreateMsg()` sibling. Six input pins in
  `lab/frontier/screensendcmd2shell/SHA256SUMS`, eight evidence pins in
  `evidence/SHA256SUMS`. Exact fix hunk in `src/fix.patch`.
- **Replay**:
  `cd lab/frontier/screensendcmd2shell && ./harness/build.sh && ./harness/run-all.sh`
  → `RUN_ALL_OK 13 PASS / 0 FAIL` twice, input and evidence pins OK.
- **Evidence**: real 5.0.1 `screen -X` ASan `global-buffer-overflow`,
  `WRITE of size 302`, 0 bytes after the 4098-byte `SocketPath` and 62 bytes
  before the real global `attach_tty_name_in_ns`, at `attacher.c:434` ←
  `screen.c:950`; fixed 5.0.2 and safe-input arms clean. Recover-ASan + GDB
  with 600 `C` bytes shows chosen `0x43` at nine offsets in that real global.
- **Compiler negative**: Clang builds reproduce the ASan WRITE and sink/caller
  but not the named global neighbor or chosen victim bytes (11/2). R4 is
  GCC/layout-specific; GCC pins restored to 13/0 after the smoke.
- **Grade**: R1/R2/R3 confirmed on the real client; R4 LIMITED to chosen bytes
  in a real adjacent global of the ASan lab build; R5 NOT CLAIMED. Plain
  non-PIE build lands in BSS padding — negative preserved.
- **Window**: see operator registry entry for the two-pane target window;
  panes and creation time are recorded there.
- **Next owner**: operator admits on the clean replay; witness re-runs the
  same harness. The target mind owns the FindSocket/SendCreateMsg siblings and
  any pointer-bearing-layout follow-up; frontier does not duplicate that lane.
