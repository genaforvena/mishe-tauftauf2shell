# openjphcleanup2shell — admitted status (196th, 2026-11-27)

Staged by frontier from CVE-2026-111151 / GHSA-5g7q-q9vm-h587 (CWE-787, CVSS
6.9 v4.0, affected `<= 0.32.0`). Vulnerable tag `0.32.0` commit
`23c422895ce6c3a156935222e4715ee0b7be952c`; fixed tag `0.33.0` commit
`345a8bcd1c7a3908e3870797057277660a412073`; verbatim fix patch
`lab/frontier/openjphcleanup2shell/pins/fix.patch`. The two-pane window 204
(panes %414/%415, dead=0) was adopted as-is at admission; it is registered
once among 205 unique names with no duplicate CVE/GHSA or sink lane.

The vulnerable `ojph_codeblock.cpp` allocates `nominal.h * stride` elements;
the fix rounds rows up to `(nominal.h + 1u) & ~1u`. The byte-identical pinned
decoder writes `dp[stride]` at raw `ojph_block_decoder32.cpp:1155` for a
one-row codeblock. A direct sink harness with an exact 32-byte one-row buffer
gets GCC ASan `heap-buffer-overflow`, `WRITE of size 4`, 0 bytes after the
region; two-row ASan and plain controls are clean and show `ROW1_OR=b0000000`.

Registered grade at handoff: **R1 — / R2 ✓ / R3 ✓ / R4 — / R5 —**. R3 is ASan
on the pinned decoder body via the direct sink, NOT a redzone fault in the
full program: the library's slab allocator keeps 5% slack, so full vulnerable
ASan stays clean (negative preserved). No chosen-offset readback, pointer,
consumer, wire path or command was observed.

`sh build-all.sh && sh run-all.sh`: rc 0 `BUILD_OK` then `PASS=27 FAIL=0`.
Runner SHA-256 `2c02c8be816631e1c971ee854fb494a4568e61d18270339625d4c2bef4466f0e`.
ADMITTED 01:3xZ under standing #6 as the 196th declared target mind; the
staged two-pane window 204 was adopted as-is. Operator clean-archive replay
from `git archive bbedbe5b lab/frontier/openjphcleanup2shell` (15 committed
files; `runs/`, source checkouts, build directories and binaries absent):
runner sha matched, `sh build-all.sh` rc 0 `BUILD_OK`, unmodified `sh run-all.sh`
rc 0 `PASS=27 FAIL=0`. Fresh GCC ASan reports `WRITE of size 4`, 0 bytes after
a 32-byte region, at verbatim raw `ojph_block_decoder32.cpp:1155` on the exact
one-row sink; two-row ASan and plain controls are clean with
`ROW1_OR=b0000000`; gdb observes the real decoder reaching raw `:1155`.
Independent witness replay is still owed; author and operator replays are
not acceptance. R4/R5 remain NOT CLAIMED: no chosen-offset readback, pointer,
consumer, wire path or command. Next #7 experiment: drive the second-row
write out of the slab's 5% slack into a live consumer with a chosen-byte
readback, loopback only, with fixed and two-row controls.

Brief: `reports/frontier-openjphcleanup2shell.md`. Harness provenance:
`lab/frontier/openjphcleanup2shell/PROVENANCE.md`.
