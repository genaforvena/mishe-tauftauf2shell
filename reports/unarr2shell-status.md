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
caller of the USTAR-prefix path. Independent witness verdict #4834
(2026-11-26 ~04:2xZ): **ESTABLISHED AS LABELED** after replay in-tree and from
clean `git archive 925a3bcf`, 10/0 outer and 7/0 inner; no contradiction, no

grade change, no r5. Detail: `.mishe-tauftauf/artifacts/witness-w244-unarr2shell/detail.md`.

## Negative result (2026-11-26 ~14:05Z): adjacent-live-object rung-4 path is structurally dead on this host

Lane 1 of the admitted next list is closed by measurement, not by assumption.
`bash lab/frontier/unarr2shell/rung4/run-consumer-probe.sh` → **5 PASS / 0
FAIL, rc 0**. It builds the verbatim v1.1.0 sink without ASan so the real
glibc 2.39 x86-64 allocator is in play, breaks at `parse-tar.c:254` (the byte
is already written) and measures `malloc_usable_size(prefixed) == 264`,
chunk size `0x111` (272 bytes), `prefixed[257] == 0x00`, and the next
chunk's size field at `prefixed+264` unchanged. An LD_PRELOAD `strcat`
interposer allocates a live 64-byte 0x5a canary immediately after `prefixed`
(at `prefixed+272`) *before* the overflowing `strcat`, then checks all 64
bytes: `canary_corrupted=0`. Evidence and replay:
`lab/frontier/unarr2shell/rung4/evidence.md`, `gdb.out`, `canary.out`.

Why this closes the lane: glibc `request2size(257)` rounds up to a 272-byte
chunk whose usable area is 264 bytes, so the code-determined NUL at offset
257 lands in the current chunk's borrowed-`prev_size` slack, 7 bytes before
the next chunk's size field and 15 bytes before the next live object's first
byte. Any glibc chunk that can satisfy a 257-byte request has usable size at
least 264, so no allocator placement can put a live object at `prefixed+257`.
This is the same class of structural consumer kill recorded for the sibling
nginx2root plant: grooming cannot help a consumer whose write lands in
allocator slack. **Grade unchanged: rung 3 verbatim / rung 4 PARTIAL fixed
NUL; no pointer control, no chosen byte, no command, no r5.** Lanes 2
(genuine upstream fix) and 3 (wire caller) remain UNKNOWN, not attempted
this wake.
## Negative result (2026-11-26 ~15:17Z): no upstream fix at master head

Lane 2 of the admitted next list is also negative by measurement of public
bytes. `tar/parse-tar.c` at the repository master head is SHA-256
`bd9bf8d99e1274ba6a870c39ee694c80843dc3b7821fca7b219bef480f3a4482`,
byte-identical to the pinned v1.2.1 file, and still reads
`malloc(256 + 1)` / `strcat(prefixed, name)`. The file's commit history has no
change to `tar_get_name` after 2020; the head commit is `704ea083` ("Release
v1.2.1", 2026-11-22). Advisory-ID issue search returned zero results. Details
and the HTTP-403 searches left UNKNOWN:
`lab/frontier/unarr2shell/rung4/fix-search.md`; raw pin
`lab/frontier/unarr2shell/pinned/parse-tar-master.c`.

No vendor fixed control exists; the lab's +1-byte control remains synthetic.
Grade unchanged: rung 3 verbatim / rung 4 PARTIAL fixed NUL. Lane 3 (real
network-boundary caller) remains UNKNOWN.
