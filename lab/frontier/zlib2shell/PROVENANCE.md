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
The tarball is self-extracted by `run.sh` when `src/zlib-1.3.2/` is absent, so
a clean checkout of only the committed files reproduces the harness.
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

## Live gzip-over-TCP server experiment — W1 (2026-11-23 05:0xZ)

New files, all re-hashed on every run by `harness/run_tcp.sh`:

| file | sha256 |
|---|---|
| `harness/tcp_server.c` | `6acbfd28ab5e19b58078dbb4829df035dd989e64c9b4f16ab72c17b033b2af58` |
| `harness/tcp_probe.py` | `4de435162e7e48797b68f47215dd0a0253f1d6d0f891b9213925fb9c5abcae6c` |
| `harness/run_tcp.sh` | `a08850ab26416355cca6bf0a8ac8409b04273a48579a8f48140f829cf03dba2b` |

Command: `cd lab/frontier/zlib2shell && bash harness/run_tcp.sh`. Two in-tree
runs and one clean `/tmp` replay each gave **14 PASS / 0 FAIL**; normalized
trace hash
`3ae896390ce28d6ec551dbac3e8e6473fd7ae923be9cb7f42762721dbdd78d02`.

Design: the server binds a plant-started 127.0.0.1 ephemeral listener, accepts
one client, sets the accepted fd non-blocking with a 4 KiB `SO_SNDBUF`
(overridable through `TCP_SNDBUF`), `gzdopen()`s it, writes a 1-byte probe and
`Z_SYNC_FLUSH` so `gz_init()` allocates `state->in` before the caller buffer
(the documented glibc guard caveat), then `malloc()`s 100000 bytes, reads the
client's own incompressible request into them, `gzwrite()`s those same peer
bytes back, `gzclearerr()`s and calls `gzprintf("x")`. The Python client sets
`SO_RCVBUF` 4096 for stall/slowdrain/gdb and 1 MiB for the clean drain control,
sends the 100000-byte payload, reads only the 10-byte gzip header and holds the
socket open. No zlib source is edited; only `gzwrite.c` is swapped from the
pinned parent/fixed blobs.

Observed:

- Vulnerable pin, stalled peer: ASan `heap-buffer-overflow`, `WRITE of size
  34465`, `gz_vacate` at `gzwrite.c:394`, 0 bytes after the 16384-byte region;
  stack `gzprintf :494 → gzvprintf :439 → gz_vacate :394`; `WRITTEN=65535`.
  Raw output `harness/tcp-evidence/vuln-stall.txt`.
- Vulnerable pin, peer draining through a 4 KiB window (`slowdrain`): the same
  overflow. The peer need not stop reading entirely; falling behind suffices.
- Fixed pin, stalled peer: rc 0, `PRINTF_RC=1`, ASan-clean.
- Vulnerable pin, peer draining with 1 MiB send and receive buffers: rc 0,
  `WRITTEN=100000`, `PRINTF_RC=1`, ASan-clean.
- Plain build under gdb, breakpoint after the memmove (`gzwrite.c:395`):
  `avail_in=34465`, source base offset 65535; `state->in[0]=0xb3`, `[17]=0x87`,
  `[16384]=0x86`, each equal to `payload[65535+offset]` from the bytes the peer
  actually sent — peer-supplied bytes at chosen destinations, the last one one
  byte past the object. Raw output `harness/tcp-evidence/vuln-gdb.txt`.

Control tuning negatives preserved: with the client's default ~128 KiB receive
window the whole 100 KiB response fit and no EAGAIN occurred (all modes
`WRITTEN=98304`, no ASan); with a 4 KiB client window but a 4 KiB server send
buffer, even the "draining" client hit EAGAIN and overflowed — that
configuration is now the positive `slowdrain` case, and the clean drain
control raises both buffers; in the first plain build the request buffer was
allocated before the first `gzwrite()`, so `state->in` did not exist yet,
glibc placed the request below it, the guard returned early and the breakpoint
was never hit. The server now forces `gz_init()` before that allocation.

Ceiling: a live loopback gzip server whose heap write is triggered by the
peer's flow-control behaviour and whose copied bytes are the peer's own
request bytes. Still rung 4: no pointer redirect, no control-flow hijack, no
command, no remote client beyond the plant's own loopback process. Rung 5
remains UNKNOWN.

## Heap layout under the 34465-byte copy — W2 (2026-11-23 05:2xZ, author-only)

Bounded rung-5 feasibility check on the plain vulnerable server from W1.
Reproduce with `python3 harness/layout_probe.py --out <file>`: it builds from
the pinned tarball with `gzwrite.c.parent` swapped, stops at `gzwrite.c:389`
(before the memmove), walks the chunks following `state->in` and scans the
destination range for code pointers. The canonical output is
`harness/tcp-evidence/layout-repro.txt`; `layout-post-memmove.txt` is the
separate post-copy gdb walk whose first following chunk header reads as peer
bytes. The post-copy walk was made with a one-off variant of `tcp_probe.py`
that reports `PEER_BYTE_CHECK=FAIL` at the pre-copy breakpoint by design; the
committed probe avoids that confusion.

At the pre-memmove breakpoint: `state=0x5555555762d0`,
`state->in=0x5555555763f0`, stale `next_in=0x5555555cdbaf`, `avail_in=34465`
(addresses are ASLR-dependent; sizes and relationships are the evidence).
Walking glibc chunks from `state->in`: chunk0 size 0x4010 is `state->in`;
chunk1 size 0x2010 at `0x...7a400` is `state->out`; chunk2 size 0x1760 at
`0x...7c410` is `state->strm.state` (deflate internal state); chunks3-6 are
0x10010 each; chunk7 size 0x186b0 at `0x...5bdbb0` is the 100000-byte caller
`req` buffer, whose `+65535` offset is the stale source pointer. The
34465-byte copy therefore covers all of `state->out`, all of the deflate
state and about the first 3.8 KiB of the following 64 KiB chunk. After the
copy, the first following chunk's size field reads
`0xec4760c5bf4a1ff8` — peer bytes have replaced live heap metadata.

A scan of the whole pristine 34465-byte destination range for 8-byte-aligned
qwords pointing into executable mappings found 0 hits across 5 executable
ranges; 13 qwords look like heap pointers. No function pointer lies in the
range in this server, so this overwrite has no direct call target to
redirect; the later `free()` calls see corrupted metadata, which is the crash
already recorded. Author-side feasibility negative, not a witness verdict; it
does not exclude a different application shape with a callable pointer inside
the overwritten range. Rung 5 remains UNKNOWN.

## Callable-pointer rewrite attempt with a real libuv consumer — W3 (2026-11-23 06:0xZ, author-only)

New files: `harness/uv_server.c`, `harness/uv_probe.py`, `harness/run_uv.sh`,
raw output in `harness/uv-evidence/`. `bash harness/run_uv.sh` builds the
vulnerable and fixed non-PIE servers from the pinned tarball (only
`gzwrite.c` swapped), calibrates the heap delta under gdb, then runs a stalled
crafted peer, a fixed-build control and a draining-peer control on a
plant-started 127.0.0.1 listener. Trace hash at staging:
`39c477c855862aa4f3fc37c04e81396b859afef79016014a56b4c1c732dd33c6`.

The server allocates a real `uv_async_t` after `gz_init()` so a larger stalled
request can reach it: at the breakpoint `state->in=0x4233f0`, handle
`0x46ae30` (delta 293440), handle size 128, `async_cb` at offset 96, heap end
`0x46b000`, top chunk `0x46aef0`, stale source base `req+65535`. A 359400-byte
request leaves `avail_in=293865`, enough to cover the handle. The peer payload
places the string `id>a` at the handle's `data` field and `system@plt` at
`async_cb`; the original message-chunk and top-chunk headers must be preserved
in the same payload so zlib's error path and glibc's allocator survive the
copy. These preserved offsets are build-specific and gdb-derived: they are a
lab condition, not a claimed wire-only exploit.

Measured (raw `harness/uv-evidence/callback-rewrite-gdb.txt`): after the
memmove the handle begins `69 64 3e 61 00...` (`id>a`) and its `async_cb`
field reads `50 87 c5 f7 ff 7f 00 00` = `0x7ffff7c58750`, exactly the
`SYSTEM_ADDR` the server printed in that run. Peer bytes therefore rewrote a
function pointer in a real event-loop consumer to `system()`. But
`uv_run()` then faults inside `libuv.so.1` before dispatch; the marker file is
absent (`MARKER=0`), `SERVER_RC=-11`. Even with the handle bytes preserved
verbatim, `uv_run()` faults, so collateral heap state, not the rewritten
callback alone, blocks this consumer. Fixed build: `PRINTF_RC=1`, `UV_RAN=1`,
rc 0, no marker. Vulnerable + draining peer: `WRITTEN=359400`, `UV_RAN=1`,
rc 0, no marker. `system@plt` is a non-PIE convenience; no command executed.

Disposition: rung-4 mechanics strengthened to a peer-chosen callback pointer
in a real heap consumer, but **no observed command side effect**. This is a
rung-5 negative for this application shape, not a witness verdict and not
evidence against another consumer with less collateral state. Rung 5 remains
UNKNOWN.
