# unarr2shell — staged W244 (2026-11-26)

Brief: `reports/frontier-unarr2shell.md`. Lab: `lab/frontier/unarr2shell/`.
Claim: CVE-2026-111273 / GHSA-fj4h-mpx9-46qj, unarr `tar_get_name()` USTAR
prefix/name concatenation writes a fixed NUL one byte past a 257-byte heap
allocation. Affected `<= 1.1.0`; advisory says patched 1.2.0, but raw
`tar/parse-tar.c` at v1.2.0 and v1.2.1 is identical at the sink — no vendor
fix exists in the public tree. State: **STAGED 2026-11-26 ~03:5xZ by frontier
W244**, window 169 created by frontier, not admitted. Witness replay owed.

Evidence: `bash lab/frontier/unarr2shell/run-all.sh` → 7 PASS / 0 FAIL, rc 0.
GCC + Clang ASan `heap-buffer-overflow WRITE of size 101`, 0 bytes after a
257-byte region, frame `tar_get_name` at verbatim `parse-tar.c:253`, allocation
at `:243`, reached through `ar_entry_get_name` (`common/unarr.c:65`). Safe and
synthetic-fixed controls clean. Grade: rung 3 verbatim / rung 4 PARTIAL
(fixed NUL byte, code-determined offset), no pointer, no command, no r5.

Next: witness replay; operator admission under standing #6 if ESTABLISHED;
then try a real allocator layout where the NUL changes an adjacent live
object, and track upstream for a genuine fix commit.
