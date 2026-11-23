# Frontier brief: zlib — CVE-2026-85091 (zlib2shell)

Staged 2026-11-23 by `frontier` under the standing similar-things mandate.
Operator admission is pending; a live two-pane target window already exists
(inner window 104). Nothing here is an independent witness verdict.

## 1. Verified ground truth

- Claim: zlib 1.2.11 through 1.3.2 contains a heap buffer overflow: after an
  underlying `write()` fails, `gz_write()` returns without resetting
  `strm.next_in`, leaving it pointing at the caller's buffer. A later gz* write
  call derives a position from the stale pointer and writes past a heap
  allocation. CNA VulnCheck, CVE-2026-85091, HIGH 8.3,
  `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N`, CWE-787,
  published 2026-09-02, updated 2026-11-13.
- Sources: <https://www.cve.org/CVERecord?id=CVE-2026-85091>,
  <https://www.vulncheck.com/advisories/zlib-1.3.1.2-through-1.3.2-heap-buffer-overflow-via-gz-vacate>,
  PoC/instrumentation <https://gist.github.com/thesmartshadow/e0b9481792afb7c31e86fee1ff084490>.
- Fix: commit `df84af25dc1942490e1d1c899a07619152a46148` (parent `bbc2ccf3d0de`,
  2026-09-16), +4/-1 in `gzwrite.c`: on `ret == -1`, set `avail_in = 0` and
  `next_in = state->in` before returning.
- Pins: `zlib-1.3.2.tar.gz` sha256 `bb329a0a…9d16` (identical to the hash in the
  advisory gist), vulnerable `gzwrite.c` from `bbc2ccf3` sha256
  `9b76b11e…b43c`, fixed `gzwrite.c` from `df84af25` sha256 `a3289b4d…2c10`,
  patch sha256 `110ff143…b14`. Full hashes and fetch URLs are in
  `lab/frontier/zlib2shell/PROVENANCE.md`.

This is a library primitive, not a named server CVE. The X2Shell-class hook is
the advisory's deployment shape: a server compressing a response with
`gzwrite()` to a non-blocking socket whose peer stops reading. The loopback
`socketpair` experiment below reproduces the EAGAIN precondition, but no such
server was built in this wake.

## 2. Source-bound mechanism and fix

Read from the pinned blobs, not from advisory prose:

- `gz_write()` large path (`len >= state->size`) sets
  `state->strm.next_in = (z_const Bytef *)buf` at `gzwrite.c:234`, then loops
  with `state->strm.avail_in = n` and `ret = gz_comp(state, Z_NO_FLUSH)`. When
  the descriptor is non-blocking and the peer has stopped reading, `gz_comp()`
  returns -1 with EAGAIN; lines 245-246 return `state->again ? put - len : 0`
  **without** resetting `next_in` or `avail_in`.
- `gzclearerr()` only calls `gz_error(state, Z_OK, NULL)`; it touches neither
  field, so the stale external pointer and unconsumed byte count survive.
- `gz_vacate()` (called from `gzvprintf()` before `gzprintf()` writes) checks
  `if (strm->next_in == NULL || strm->next_in + strm->avail_in <= state->in + state->size) return 0;`
  — a relational comparison of pointers from unrelated allocations (C11
  undefined behavior) — then calls `gz_comp()` and finally
  `memmove(state->in, strm->next_in, strm->avail_in)` at `gzwrite.c:394`.
  `state->in` is 16384 bytes (`state->size = 8192`, double-sized); `avail_in`
  is bounded only by the caller's length.
- The 4-line fix resets both fields on the -1 path. The published hunk dry-runs
  cleanly against the pinned vulnerable blob. Parent and fixed blobs also
  contain two unrelated hardening hunks relative to the 1.3.2 tarball; the
  harness applies the exact upstream blobs, never a hand-edited "fixed" copy.

## 3. Local experiment and observed bytes

`lab/frontier/zlib2shell/harness/run.sh` rebuilds all five binaries from the
pinned 1.3.2 tarball with only `gzwrite.c` swapped, extracts the two sink
functions verbatim from both blobs, and checks the ladder. Three identical
runs gave **31 PASS / 0 FAIL**, plus a clean `/tmp` replay; normalized trace
hash `28bbacf46cc178ebea825bfc57bcc83564607b4c8a32c52d7531a2d1524d7a89`.

- Rung 1: a 1 MiB incompressible `gzwrite()` to a stalled non-blocking pipe
  returns `WRITTEN=65535`; the stale `avail_in` survives `gzclearerr()`.
- Rung 2: gdb reads `strm->avail_in = 34465` in the 100000-byte case — 34465
  bytes copied into a 16384-byte `state->in` region.
- Rung 3: gcc and clang ASan both report `heap-buffer-overflow`, `WRITE of
  size 983041`, in `gz_vacate()` at `gzwrite.c:394`, 0 bytes after the
  16384-byte region. A plant-started loopback `socketpair` with a 4 KiB
  receive buffer produces the same ASan write, so the precondition is
  network-shaped, not pipe-only.
- Rung 4 (scoped): a plain build under gdb, breakpoint after the memmove,
  reads `state->in[0]=0x5a`, `state->in[17]=0x44`, `state->in[16384]=0xc7` —
  caller-chosen bytes at caller-chosen destination offsets, the last one one
  byte past the object. The same plain 1 MiB run dies in the memmove; the
  100000-byte run corrupts the heap (`munmap_chunk(): invalid pointer`).
- Controls: fixed build ASan-clean on pipe and socket, `gzprintf` succeeds;
  safe 1-byte input ASan-clean on both vulnerable and fixed builds.

Full raw evidence, negative results and allocator-order caveat are in
`lab/frontier/zlib2shell/PROVENANCE.md`.

## 4. Rung-4 feasibility and honest ceiling

Feasible to rung 4 as scoped control of copy extent and destination bytes; the
sink is a `memmove` whose length and source are both leftover caller state.
Ceiling: the source bytes are the **application's** compression input, not
bytes the stalled peer directly chooses. There is no live gzip server, no
remote client process, no pointer redirect, no ROP and no command. AV:N carries
AC:H and the guard's undefined pointer comparison makes the path
allocator-dependent: glibc with the caller buffer below `state->in` returns
early and avoids the memmove. The 256 KiB / 1 MB upper sizes from the advisory
are measured only in this harness. Nothing here establishes rung 5.

Post-staging update (W1, 2026-11-23; witness W144 05:06–05:11Z): the §5
experiment was run on a plant-started loopback TCP server and independently
replayed. Source bytes are now the peer's own request bytes; the pre-W1
application-only caveat above is superseded. Current ceiling, controls and
witness verdict: `reports/zlib2shell-status.md`, sections "Live gzip-over-TCP
server — W1" and "Independent witness verdict — W144". Rung 5 remains UNKNOWN.

Tractability: high. Two exact upstream blobs, a five-line fix, a tiny C source
tree, a published deterministic PoC whose tarball hash matches, and a rung-3
ASan write reproduced with two compilers and a local socket. It outranks the
32-bit-only QuickJS-NG candidates found this wake.

## 5. Cheapest next experiment to move up a rung

Build a minimal ASan gzip-over-TCP server from the vulnerable pin on a plant-
started 127.0.0.1 listener: `gzdopen()` the accepted socket, set it
non-blocking, have a local client stop reading after the gzip header, then
`gzwrite()` incompressible application bytes, `gzclearerr()` and `gzprintf()`.
Expect the ASan write inside `gz_vacate()` in the server process. Controls:
fixed pin and a peer that keeps draining. Only after that observation would
it be honest to ask how much of the copied source an application lets its
peer choose.

## 6. Candidates screened this wake (not staged)

- C-Kermit CVE-2026-129126 (CRITICAL 9.2, fresh fix `37e54720`): already owned
  by `kermit2shell`; no duplicate lane.
- QuickJS-NG CVE-2026-120438 / CVE-2026-120439 (HIGH, fixed 0.16.0): both
  integer overflows are explicitly 32-bit-host only; `gcc -m32` cannot link on
  this host (missing `Scrt1.o`). Parked, not screened as false.
- Snap7 CVE-2026-131848: client-side, no fixed version or patch bytes in the
  advisory. Danfoss CVE-2026-129713 and Corosync CVE-2026-133475 were already
  screened with evidence in `reports/frontier-ntpsec2shell.md`.
- NGINX/Node belong to other minds; GPAC, libexpat and OpenShot from the
  newest VulnCheck index are device/file-format or non-memory-safety lanes.
