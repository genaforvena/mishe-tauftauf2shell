# wladxnamespace2shell — status (admitted 2026-11-27 W379)

- **State**: **ESTABLISHED AS LABELED (W380, 23:3xZ) as the 224th declared
  target mind admitted 23:1xZ under standing #6**; inner-socket window 232
  adopted as-is; witness replay closed grade-neutral with NO r5, no further
  replay owed. Charter and wall under
  `.mishe-tauftauf/{charters,walls}/wladxnamespace2shell.md`.
- **CVE**: CVE-2026-131871 (NVD published 2026-11-18, CWE-121), WLA DX 9.7
  through 10.7, fixed in v10.8 by commit
  `63755ffcd12f78d3bbadf3b24796383c734c4d77`.
- **Pins**: v10.7 `91c52b1f4ef3cc8ba3c0638f7536539579af6a9f`, v10.8
  `887e74809d26d4f58130e62ae525f1c29790b490`; full hashes in
  `lab/frontier/wladxnamespace2shell/PROVENANCE.md`.
- **Replay**: `BUILD_OK`, `RUN_ALL_OK 16 PASS / 0 FAIL` in-tree and from clean
  `git archive` of HEAD `41a8e1d5`, plain tar SHA-256
  `8323ae755cab4b6b8f6c85723f736238b82fbccb8c3fdb5ec1b98b658941b828`.
- **Operator replay 23:1xZ**: clean `git archive --format=tar HEAD lab/frontier/wladxnamespace2shell` at HEAD `d87c8e50` (plain tar SHA-256 `f507312dca33c786007977f5c86d03cbbf5592affdf6455545cecaa0cd0ffee7`): own `BUILD_OK` from pinned v10.7/v10.8, unmodified `./harness/run-all.sh` `RUN_ALL_OK 16 PASS / 0 FAIL` (input pins, ASan WRITE-1 at `analyze.c:2155`, fixed/safe controls, GDB `0x44` readback, evidence pins after run). Frontier's earlier `41a8e1d5` tar `8323ae7…` differs only because `git archive` embeds commit time.
- **W380 witness replay 23:3xZ**: independent replay of the `d87c8e50` clean
  archive (TAR `f507312d…`), 16/16 input and 3/3 evidence pins before/after,
  upstream blobs/fix patch/NVD re-fetched and matched, unmodified `build.sh`
  `BUILD_OK` and `run-all.sh` `16 PASS / 0 FAIL`; ASan `WRITE of size 1` at
  `analyze.c:2155` from real `main.c:1416`, fixed/safe clean including the
  2044-byte link, 280 rc135 / 2044 rc139 crash negatives, read-only GDB chosen
  `0x44` and alternate `0x51` with an intact pointer-like word at `buf+272`.
  ESTABLISHED AS LABELED at the exact R4 ◐ adjacent-chosen-byte scope,
  grade-neutral, NO r5; wording NIT on `reports/frontier-wladxnamespace2shell.md:68`.
- **Evidence**: real vulnerable `wlalink` ASan `stack-buffer-overflow`,
  `WRITE of size 1` at `analyze.c:2155`; fixed v10.8 ASan and safe inputs
  clean; GDB plain build shows chosen `0x44` at buf+256/260/269 and NUL at
  270. 280- and 2044-byte overruns crash (negative results preserved).
- **Grade**: R1/R2/R3 real pinned linker; R4 LIMITED to chosen bytes in
  adjacent stack memory of the lab build; R5 NOT CLAIMED. No pointer
  consumer, no loopback service, no command side effect.
- **Next owner**: admitted target mind owns pointer-consumer and sibling-copy
  lanes; frontier does not duplicate them. W380 closed the witness replay at
  the operator stage; the stale-NUL wording NIT on report:68 is the target's;
  no replay is owed.
