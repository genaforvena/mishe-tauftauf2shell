# unarr2shell — admitted W244 (2026-11-26)

Brief: `reports/frontier-unarr2shell.md`. Lab: `lab/frontier/unarr2shell/`.
Claim: CVE-2026-111273 / GHSA-fj4h-mpx9-46qj, unarr `tar_get_name()` USTAR
prefix/name concatenation writes a fixed NUL one byte past a 257-byte heap
allocation. Affected `<= 1.1.0`; advisory says patched 1.2.0, but raw
`tar/parse-tar.c` at v1.2.0 and v1.2.1 is identical at the sink — no vendor
fix exists in the public tree. State: **ADMITTED 2026-11-26 ~04:1xZ by operator under standing #6 as the 161st
declared target mind**; window 169 adopted; hy4-flash route and three generated
wake units remain missing (person-reserved). Frontier staged it ~03:5xZ; the
unmodified `run-witness.sh` replay passed in-tree and from a clean
`git archive 925a3bcf`.

Evidence: `bash lab/frontier/unarr2shell/run-witness.sh` → `REPLAY_PASS=10/0`,
inner `TOTAL: 7 PASS / 0 FAIL`, rc 0, seven exact pins, in-tree and from a clean
`git archive 925a3bcf`. `bash lab/frontier/unarr2shell/harness/run-all.sh` → 7 PASS / 0 FAIL, rc 0.
GCC + Clang ASan `heap-buffer-overflow WRITE of size 101`, 0 bytes after a
257-byte region, frame `tar_get_name` at verbatim `parse-tar.c:253`, allocation
at `:243`, reached through `ar_entry_get_name` (`common/unarr.c:65`). Safe and
synthetic-fixed controls clean. Grade: rung 3 verbatim / rung 4 PARTIAL
(fixed NUL byte, code-determined offset), no pointer, no command, no r5.

Next: push rung 4 by placing a live allocation adjacent to `prefixed` under a
real (non-ASan) allocator and observing whether the NUL changes an adjacent
object before the consumer; track upstream for a genuine fix commit and
replace the synthetic +1-byte control; check for a real network-boundary
caller of the USTAR-prefix path. No witness verdict was claimed by admission;
the operator's two replays are not independent acceptance.
