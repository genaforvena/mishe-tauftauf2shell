# uxplaypin2shell — status (admitted 2026-11-27)

State: **ADMITTED 16:1xZ under standing #6 as the 216th declared target
mind; independent witness replay still owed.** Brief:
`reports/frontier-uxplaypin2shell.md`. Lab, pins and provenance:
`lab/frontier/uxplaypin2shell/PROVENANCE.md`. Staged inner-socket window 224
(`%454`/`%455`, `dead=0`) adopted as-is; registry 225/225 unique. Wake units,
routes and sync stay person-reserved.

GHSA-479c-ww7g-wgp8, High, CWE-121 + CWE-476, "No known CVE"; affected UxPlay
`< 1.73.7`, patched `1.73.7`, fix commit
`746ec0eac21a7cf32ec39dbf105d564b36eab5e1`. Pinned v1.73.6
`lib/raop_handlers.h:366` copies an attacker-chosen plist proof length into
`proof[64]`; pre-authentication reachable.

Author result: `sh harness/run-all.sh` at 4 pins gives `RUN_ALL_OK 10 PASS /
0 FAIL`, summary SHA-256
`d3faf93535892ff5e3fdd4aba3bf6c2aa45da6cf273bd7cbf441af00a7ade994`.
Clean `git archive --format=tar abb7f49c` replay: 4/4 pins, byte-identical
summary, plain-tar SHA-256
`8d72e4a6703814a3e993e5407cef41f321be5aead61e918e884fdc2f6e297967`.
ASan `WRITE of size 128` at the pinned sink; plain no-PIE GDB shows
`saved rip = 0x4343434343434343`; fixed `sizeof(proof)` arm and 20-byte safe
input are clean.

Operator clean replay at 16:19Z from a private `git archive --format=tar
abb7f49c lab/frontier/uxplaypin2shell` tree: plain-tar SHA-256
`8d72e4a6703814a3e993e5407cef41f321be5aead61e918e884fdc2f6e297967`,
4/4 pins OK, rc 0, `RUN_ALL_OK 10 PASS / 0 FAIL` and summary SHA-256
`d3faf93535892ff5e3fdd4aba3bf6c2aa45da6cf273bd7cbf441af00a7ade994`
byte-identical to the author run, including the GDB saved-RIP check.

Grade: R1/R2/R3 ✓; R4 DEMONSTRATED at the pinned-sink/argv lab scope under
disclosed no-PIE/no-canary/no-fortify conditions; R5 NOT CLAIMED (no live
listener, wire request, marker or command effect). `established:false` until
a witness verdict lands.
