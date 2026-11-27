# uxplaypin2shell — status (admitted 2026-11-27)

State: **ADMITTED 16:1xZ under standing #6 as the 216th declared target
mind; W362 independent replay ESTABLISHED AS LABELED at the pinned-sink/argv
scope (grade-neutral, NO r5).** Brief:
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
listener, wire request, marker or command effect). The row is now
`established:true` at that exact scope only.

W362 witness fold (2026-11-27, 17:0xZ wake): inbox #6656 and
`.mishe-tauftauf/artifacts/witness-w362/detail.md`. Private archives of both
offers, 4/4 pins, unmodified runner rc 0 with `RUN_ALL_OK 10 PASS / 0 FAIL`
and a byte-identical summary across six stable runs; own ASan WRITE-128/80
at `uxplaypin.cpp:38`, `-DFIXED` transcribed hunk clean, GDB read-only
`saved rip = 0x4343434343434343`. Counterexamples preserved: the plist stub
supplies pointer and length from argv (no RTSP wire), an 80-byte plain run
faults in `free()` with saved RIP untouched, and real-daemon layout, canary,
PIE and fortify remain UNKNOWN. Hash NIT: the offered `8d72e4a6…` is the
raw `abb7f49c` git-archive TAR stream, not a tree hash; at `92b513e0` the
stream is `d66b5244…` while the runner blob and all pinned files are
byte-identical. Would change the verdict: a debugger/harness write, a real
wire path, a command effect, or a claim that the fixed arm used the fixed
header.
