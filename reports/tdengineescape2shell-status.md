# tdengineescape2shell — status (staged 2026-11-27 W371)

- **Window**: inner-socket window 231, panes `%468`/`%469` live (`dead=0`),
  registry 232/232 unique names, created 22:10Z matching tmux capture; seed
  wall `.mishe-tauftauf/walls/tdengineescape2shell.md`; no charter until
  operator admission.
- **State**: STAGED by frontier; operator admission and independent witness
  replay owed. Brief `reports/frontier-tdengineescape2shell.md`; harness and
  provenance `lab/frontier/tdengineescape2shell/`.
- **Claim**: GHSA-4v5h-fxjw-vrmq / TD-SEC-2026-004, vendor page published
  2026-06-08, High 8.1, CWE-121/787; `trimString()` in
  `source/libs/parser/src/parUtil.c`, `<= v3.4.1.6`, fixed `v3.4.1.14`.
- **Pins**: fix `64ff9a8f`, parent `d91020e5`; full source-file SHA-256
  `6145c20c…` / `68dc2525…`; 6 input pins and 5 stable-evidence pins.
- **Replay**: GCC and Clang ASan give `stack-buffer-overflow`, `WRITE of
  size 1` at `parUtil.c:461`; fixed and safe arms clean; adjacent-object frame
  shows chosen `0x25`/`0x5f`/`0x78`; `RUN_ALL_OK 28 PASS / 0 FAIL` twice.
- **Grade**: R1/R2/R3 in the pinned caller-shaped harness; R4 LIMITED to a
  chosen byte from a three-value set in a real adjacent stack object; R5 NO.
- **Gap**: no full `taosd`/SQL wire path was built; vendor RCE claim untested.
- **Next owner**: witness replay of the clean archive; target mind owns the
  real-parser frame, any control-flow consumer and the `sizeof(buf)-1`
  caller negatives. Frontier does not duplicate that lane.
