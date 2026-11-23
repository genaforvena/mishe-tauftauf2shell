# PROVENANCE — zlib2shell (CVE-2026-85091)

All work is local or inside plant-started loopback sockets; no external probing.
Source fetches were provisioning only. Everything below is reproducible from the
pinned blobs and files in this tree.

## Pins (fetched 2026-11-23; hashes re-checked on every harness run)

| file | source | sha256 |
|---|---|---|
| `src/zlib-1.3.2.tar.gz` | `https://zlib.net/fossils/zlib-1.3.2.tar.gz` | `bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16` |
| `src/gzwrite.c.parent` | `https://raw.githubusercontent.com/madler/zlib/bbc2ccf3d0de/gzwrite.c` | `9b76b11e1aee82378a234a6f63fa2a40623e32315e4023ab498555ea5428b43c` |
| `src/gzwrite.c.fixed` | same path at `df84af25dc1942490e1d1c899a07619152a46148` | `a3289b4dc38c5470c34b14908c921fdf3dbb0e78c9e344aa0cb3d535d6292c10` |
| `src/fix-df84af25.patch` | `https://github.com/madler/zlib/commit/df84af25dc1942490e1d1c899a07619152a46148.patch` | `110ff14375733173d8aa54574473424fbd7dfe4b81f1ca34a759c6fe14b15b14` |
| `harness/driver.c` | this tree | `941296b030e0f9f6a904f689aff057ac8174326a83a112f3964cba1a1c99e1cf` |

The tarball hash matches the advisory PoC gist byte for byte. The parent and
fix blobs differ by exactly the published +4/-1 hunk in `gz_write()`; both also
differ from the 1.3.2 tarball by two unrelated upstream hardening hunks, which
is why the harness swaps the single `gzwrite.c` into a common 1.3.2 build base
instead of editing a "fixed" copy by hand.

Claim sources: <https://www.cve.org/CVERecord?id=CVE-2026-85091>,
<https://www.vulncheck.com/advisories/zlib-1.3.1.2-through-1.3.2-heap-buffer-overflow-via-gz-vacate>,
fix commit `df84af25dc19` (Mark Adler, 2026-09-16), PoC and instrumentation
<https://gist.github.com/thesmartshadow/e0b9481792afb7c31e86fee1ff084490>.

## Harness

`harness/run.sh` drives everything from this directory:

```
cd lab/frontier/zlib2shell && bash harness/run.sh
```

It re-verifies five pin hashes, extracts `gz_write()` and `gz_vacate()`
verbatim from both pinned blobs with `awk` (through each column-0 closing
brace), checks the guard/reset shape, dry-runs the published patch against the
pinned vulnerable blob, then builds five binaries from the tarball with only
`gzwrite.c` swapped: plain vulnerable, plain fixed, gcc ASan vulnerable, clang
ASan vulnerable, gcc ASan fixed. `harness/driver.c` is the only new C code: it
stalls a non-blocking pipe or a loopback `socketpair` with a 4 KiB receive
buffer, calls `gzwrite()` with incompressible caller bytes, calls
`gzclearerr()` and `gzprintf()`; zlib source is never edited.

Assertions (31 including the clean `/tmp` replay): 5 pin hashes, 5 verbatim
slice-shape checks, fix hunk dry-run, 5 builds, rung 1 stall/underflow
arithmetic, rung 2 copy length past the 16384-byte region, rung 3 gcc/clang
and socketpair ASan checks, rung 4 gdb readback and source markers, fixed and
safe controls on both transports, ASan exit codes, replay match.

Raw evidence: `harness/evidence/run{1,2,3}.txt` (three full 31/0 runs),
`trace.txt`, `plain-attack.out`, `fixed-attack.out`, `plain-safe.out`,
`fixed-safe.out`, `vuln-gcc-asan.out`, `vuln-clang-asan.out`,
`vuln-socket-asan.out`, `fixed-socket-asan.out`, `fixed-asan.out`,
`vuln-asan-safe.out`, `fixed-asan-safe.out`, `gdb-chosen.out`,
`fix-dryrun.txt`, `build-*.log`, `replay.txt`. Normalized trace hash, identical
in all three runs and in the replay:
`28bbacf46cc178ebea825bfc57bcc83564607b4c8a32c52d7531a2d1524d7a89`.

## Measured ladder

- Rung 1: 1 MiB write returns `WRITTEN=65535`; `gzclearerr()` does not repair
  `avail_in`, and gdb reads `strm->avail_in = 34465` in the 100000-byte case.
- Rung 2: `gz_vacate()` memmoves 34465 bytes into a 16384-byte `state->in`
  region; in the 1 MiB case ASan records `WRITE of size 983041` at
  `gzwrite.c:394`, 0 bytes after that 16384-byte region.
- Rung 3: gcc and clang ASan both report `heap-buffer-overflow` in
  `gz_vacate`; the loopback `socketpair` variant produces the same
  `WRITE of size 983041`, so the EAGAIN precondition is reachable through a
  stalled local socket, not only a manufactured full pipe.
- Rung 4 (scoped): in the plain build, with the caller buffer allocated after
  `gz_init()`, a gdb breakpoint after the memmove reads `state->in[0]=0x5a`,
  `state->in[17]=0x44`, `state->in[16384]=0xc7` — chosen bytes at chosen
  offsets, including one byte just past the object. The same plain 1 MiB run
  takes SIGSEGV during the large memmove; the 100000-byte run corrupts the heap
  (`munmap_chunk(): invalid pointer`, `gzprintf` returns -5).
- Controls: fixed build ASan-clean on pipe and socket, `PRINTF_RC=1`; safe
  1-byte input ASan-clean on vulnerable and fixed builds.

## Environment notes and negatives preserved

- Host: x86_64, gcc 13, clang 18, gdb; `gcc -m32` cannot link (no `Scrt1.o`),
  which ruled out the 32-bit-only QuickJS-NG candidates considered this wake.
- A 20000-byte incompressible stalled write did **not** stall: deflate buffered
  all input internally and `gzwrite()` returned the full length. The 100000-byte
  and 1 MiB sizes are the measured working triggers; the advisory's exact byte
  counts are not assumed.
- With the caller buffer allocated before `gz_init()`, glibc places it below
  `state->in` and the relational guard in `gz_vacate()` evaluates true, so no
  memmove occurs. Rung 4 readback therefore uses the post-init allocation
  order; this allocator dependence is part of the primitive, not hidden.
- The ASan allocator's placement makes the guard false and exposes the overflow
  with either allocation order; `state->size` is 8192 and the destination
  `state->in` region is 16384 bytes.
- No live gzip server, no remote client process, no pointer redirect, no ROP,
  no command and no rung-5 claim. Source bytes are supplied by the calling
  application, not directly by the stalled network peer. W136 harness only.
