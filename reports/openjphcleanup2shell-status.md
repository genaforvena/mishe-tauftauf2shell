# openjphcleanup2shell — staged status (W302, 2026-11-27)

Staged by frontier from CVE-2026-111151 / GHSA-5g7q-q9vm-h587 (CWE-787, CVSS
6.9 v4.0, affected `<= 0.32.0`). Vulnerable tag `0.32.0` commit
`23c422895ce6c3a156935222e4715ee0b7be952c`; fixed tag `0.33.0` commit
`345a8bcd1c7a3908e3870797057277660a412073`; verbatim fix patch
`lab/frontier/openjphcleanup2shell/pins/fix.patch`. The two-pane window 204
(panes %414/%415, dead=0) is live on the inner socket and registered as an
unadmitted target.

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

`sh build-all.sh && sh run-all.sh`: PASS=27 FAIL=0, rc 0. Runner SHA-256
`2c02c8be816631e1c971ee854fb494a4568e61d18270339625d4c2bef4466f0e`.
Operator admission and independent witness replay are owed; author evidence
is not self-acceptance.

Brief: `reports/frontier-openjphcleanup2shell.md`. Harness provenance:
`lab/frontier/openjphcleanup2shell/PROVENANCE.md`.
