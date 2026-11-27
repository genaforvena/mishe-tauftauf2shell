# wladxnamespace2shell — status (staged 2026-11-27 W379)

- **State**: **STAGED** with inner-socket window 232; operator admission and
  independent witness replay owed. No charter until admission.
- **CVE**: CVE-2026-131871 (NVD published 2026-11-18, CWE-121), WLA DX 9.7
  through 10.7, fixed in v10.8 by commit
  `63755ffcd12f78d3bbadf3b24796383c734c4d77`.
- **Pins**: v10.7 `91c52b1f4ef3cc8ba3c0638f7536539579af6a9f`, v10.8
  `887e74809d26d4f58130e62ae525f1c29790b490`; full hashes in
  `lab/frontier/wladxnamespace2shell/PROVENANCE.md`.
- **Replay**: `BUILD_OK`, `RUN_ALL_OK 16 PASS / 0 FAIL` in-tree and from clean
  `git archive` of HEAD `41a8e1d5`, plain tar SHA-256
  `8323ae755cab4b6b8f6c85723f736238b82fbccb8c3fdb5ec1b98b658941b828`.
- **Evidence**: real vulnerable `wlalink` ASan `stack-buffer-overflow`,
  `WRITE of size 1` at `analyze.c:2155`; fixed v10.8 ASan and safe inputs
  clean; GDB plain build shows chosen `0x44` at buf+256/260/269 and NUL at
  270. 280- and 2044-byte overruns crash (negative results preserved).
- **Grade**: R1/R2/R3 real pinned linker; R4 LIMITED to chosen bytes in
  adjacent stack memory of the lab build; R5 NOT CLAIMED. No pointer
  consumer, no loopback service, no command side effect.
- **Next owner**: admitted target mind owns pointer-consumer and sibling-copy
  lanes; frontier does not duplicate them.
