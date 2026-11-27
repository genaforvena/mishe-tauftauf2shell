# lrzszprocheader2shell — status (admitted 2026-11-27 W352)

State: **ADMITTED 17:3xZ under standing #6 as the 218th declared target mind**;
independent witness replay owed. Window 226 (inner socket, two panes) created
2026-11-27 ~17:17Z and adopted as-is; wake units, routes and sync stay
person-reserved. Brief: `reports/frontier-lrzszprocheader2shell.md`. Lab and
pins: `lab/frontier/lrzszprocheader2shell/PROVENANCE.md`. Charter and seed wall
are under `.mishe-tauftauf/{charters,walls}/lrzszprocheader2shell.md`.

Operator clean replay at 17:34Z from `git archive --format=tar 4678a157`
(plain-tar SHA-256 `06329456e5f7920d2b58f226c58f6b7d0034a76482075bc335b7cce839958ffa`):
6/6 `SHA256SUMS` pins matched, rc 0, unmodified `sh harness/run-all.sh`
`RUN_ALL_OK 5 PASS / 0 FAIL`, and the stable ASan markers `WRITE of size 12001`
at `src/lrz.c:1220` with the 8192-byte allocation at `:1217` reproduced. An
earlier clean replay of the staging commit `2de80271` was also 5 PASS / 0 FAIL
but its `SHA256SUMS` still pinned the volatile ASan log; `4678a157` excludes it
and is the admission basis.

CVE-2026-105842 / GHSA-3cw3-cf87-8pwp; affected lrzsz `< 0.13.0`, fixed 0.13.0
`b18b579272fa94748388364014f22e20712288d4`; pre-fix parent
`b1fc8a01e3a074f8462a29dca45ed7c8fd2ef665`, fix commit
`f8caa7b1b1a3a1bb50cf08677b15be7b17c2956f`. Pinned
`src/lrz.c:1217-1220` copies a sender-chosen ZMODEM filename into an 8192-byte
`malloc(PATH_MAX*2)` with `strcpy`; fixed commit uses `strdup`.

Grade: R1/R2/R3 ✓ and R4 DEMONSTRATED at the **pinned-sink lab scope** —
ASan `WRITE of size 12001` with byte fill 0x43 at `src/lrz.c:1220`, zero bytes
past the 8192-byte allocation from `:1217`; 16-byte safe arm clean; fixed
commit clean with the same 12000-byte name. R5 NO: no shell command, marker,
chosen-address write, and no live wire session yet. `established:false` until a
witness verdict lands. The cheapest follow-through is a real loopback ZFILE
frame replay into an unmodified `lrz`; until measured, the label stays
pinned-sink only.
