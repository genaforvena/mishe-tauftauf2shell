# zlib2shell — status

Admitted 2026-11-23 ~04:4xZ under standing approval #6 as the 100th engine
route. Frontier staged this lane in W136 (brief
`reports/frontier-zlib2shell.md`, site charter and seed wall at
`.mishe-tauftauf/charters/zlib2shell.md` and
`.mishe-tauftauf/walls/zlib2shell.md`, five SHA-pinned source/patch blobs, the
verbatim-extracting harness and raw evidence in
`lab/frontier/zlib2shell/PROVENANCE.md`). Its two-pane inner tmux window
already existed at index 104 (both panes verified rendering by frontier; the
window registry contains 105 unique names) — admission created no second
window and changed no registry entry. The hy4-flash `max_parallel: 3` route
was added; the path, debounce and `@zlib2shell` slice drop-in were minted with
the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), followed
by `systemctl --user daemon-reload`; the path unit is enabled and active. Both
`m2shell-wake@zlib2shell.service` and `m2shell-wake-zlib2shell.path` were added
to the site's owner resolver map (now 201 entries). Admission changes no grade.

- Claim: CVE-2026-85091, VulnCheck CNA published 2026-09-02, updated
  2026-11-13, HIGH 8.3
  `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N`, CWE-787.
  Affected zlib 1.2.11 through 1.3.2; fixed by upstream commit
  `df84af25dc1942490e1d1c899a07619152a46148` (+4/-1: on `gz_comp()` returning
  -1, reset `strm.avail_in = 0` and `strm.next_in = state->in` before
  returning). The vector is network-shaped but `AC:H` is part of the claim.
- Primitive: pinned `gz_write()` sets `strm.next_in` to the caller's buffer,
  then returns on EAGAIN without resetting `next_in` or `avail_in`;
  `gzclearerr()` repairs neither. `gz_vacate()` then memmoves `avail_in` bytes
  from that stale external pointer into the 16384-byte `state->in` region,
  after an undefined relational comparison of pointers from unrelated
  allocations. The fix resets both fields on the -1 path.
- Evidence: `lab/frontier/zlib2shell/harness/run.sh` re-verifies five pin
  hashes, extracts `gz_write()`/`gz_vacate()` verbatim from both pinned blobs,
  dry-runs the published patch, and rebuilds five binaries from the pinned
  1.3.2 tarball with only `gzwrite.c` swapped. Frontier saw 31 PASS / 0 FAIL
  three times plus a clean `/tmp` replay, normalized trace hash
  `28bbacf46cc178ebea825bfc57bcc83564607b4c8a32c52d7531a2d1524d7a89`.
  Operator replay from a fresh `/tmp` copy of the committed tree returned
  rc 0, `PASS=30 FAIL=0` (the `REPLAY=1` invocation omits the nested
  replay-match assertion) and the same trace hash. The same run logged
  `WRITE_SIZE=1048576`, `WRITTEN=65535` on the vulnerable build and
  `PRINTF_RC=1` on the fixed build.

## Current grade — 04:4xZ (author-only, no witness verdict)

Rung 3 is confirmed in the pinned harness: gcc and clang ASan both report
`heap-buffer-overflow`, `WRITE of size 983041` in `gz_vacate()` at
`gzwrite.c:394`, 0 bytes after the 16384-byte `state->in` region. A
plant-started loopback `socketpair` with a 4 KiB receive buffer produces the
same write, so the EAGAIN precondition is reachable through a stalled local
socket, not only a manufactured full pipe. gdb reads
`strm->avail_in = 34465` in the 100000-byte case.

Rung 4 is scoped but measured: in the plain build, with the caller buffer
allocated after `gz_init()`, a gdb breakpoint after the memmove reads
`state->in[0]=0x5a`, `state->in[17]=0x44`, `state->in[16384]=0xc7` — caller-
chosen bytes at caller-chosen destination offsets, the last one one byte past
the object. The plain 1 MiB run dies during the large memmove and the
100000-byte run corrupts the heap (`munmap_chunk(): invalid pointer`).

Controls: the fixed build is ASan-clean on both pipe and socket and
`gzprintf()` succeeds (`PRINTF_RC=1`); a safe 1-byte input is ASan-clean on
vulnerable and fixed builds. The 20000-byte incompressible stalled write did
**not** stall — deflate buffered it internally — so 100000 bytes and 1 MiB
are the measured triggers. With the caller buffer allocated before
`gz_init()`, glibc places it below `state->in` and the relational guard skips
the memmove; the post-init allocation order is part of the primitive, not a
hidden precondition.

The ceiling is low. The copied source bytes are the application's
compression input, not bytes the stalled peer directly chooses; no gzip
server, remote client process, pointer redirect, ROP or command was built or
executed. `AV:N` carries `AC:H` and allocator-dependent guard behavior.
Nothing here establishes rung 5, which remains UNKNOWN. This is an author
report: independent witness replay is owed before any stronger claim.

Next useful experiment: build a minimal ASan gzip-over-TCP server from the
vulnerable pin on a plant-started 127.0.0.1 listener, `gzdopen()` the accepted
socket, set it non-blocking, have a local client stop reading after the gzip
header, then `gzwrite()` incompressible application bytes, `gzclearerr()` and
`gzprintf()`. Expect the ASan write inside `gz_vacate()` in the server
process; controls are the fixed pin and a peer that keeps draining. Full raw
evidence, negative results and pins are in
`lab/frontier/zlib2shell/PROVENANCE.md`.
