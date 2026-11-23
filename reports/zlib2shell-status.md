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

## Current grade — 05:11Z (witness ESTABLISHED at labeled scope)

Witness W144 (2026-11-23 05:06–05:11Z) replayed both harnesses from its own
clean `git archive` of HEAD (`1d09288`; target tree unchanged `beab687..HEAD`)
with its own builds at a different `/tmp` path: base `run.sh` rc 0,
`PASS=31 FAIL=0` (plus `REPLAY=1` `PASS=30 FAIL=0`) and trace hash exactly
`28bbacf46cc178ebea825bfc57bcc83564607b4c8a32c52d7531a2d1524d7a89`; W1
`run_tcp.sh` rc 0, `PASS=14 FAIL=0` twice and trace hash exactly
`3ae896390ce28d6ec551dbac3e8e6473fd7ae923be9cb7f42762721dbdd78d02`. No
counterexample. Both claims are ESTABLISHED at the rung-4 scope labeled below;
rung 5 remains UNKNOWN. Details in "Independent witness verdict" at the end.

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

## Ceiling after W1 (witness ESTABLISHED at labeled scope)

The handoff ceiling (application-chosen source bytes, no server) is superseded
by the live loopback server result below. The source bytes are now the peer's
own request bytes and the trigger is TCP flow control, but the sink remains an
unbounded `memmove`: no pointer redirect, no control-flow hijack, no command,
no remote client beyond the plant's own loopback process. `AV:N` still carries
`AC:H` and allocator-dependent guard behavior. Nothing here establishes rung
5, which remains UNKNOWN. Witness W144 replayed both harnesses independently
and found no counterexample; both claims are ESTABLISHED at this labeled
rung-4 scope, with no replay owed.

## Live gzip-over-TCP server — W1 (2026-11-23 05:0xZ)

`harness/run_tcp.sh` builds the server from the pinned tarball with only
`gzwrite.c` swapped and drives five cases on a plant-started 127.0.0.1
listener: 14 PASS / 0 FAIL twice plus a clean `/tmp` replay; trace hash
`3ae896390ce28d6ec551dbac3e8e6473fd7ae923be9cb7f42762721dbdd78d02`. The
server `gzdopen()`s the accepted non-blocking socket, compresses the client's
own 100000 request bytes, then `gzclearerr()` / `gzprintf()`.

- Vulnerable pin, peer reads only the gzip header: ASan `heap-buffer-overflow`,
  `WRITE of size 34465` in `gz_vacate` (`gzwrite.c:394`), 0 bytes after 16384;
  `WRITTEN=65535`. A peer that keeps draining through a 4 KiB window also
  overflows — falling behind is enough.
- Fixed pin with the stalled peer, and vulnerable pin with a draining peer on
  1 MiB buffers: rc 0, `PRINTF_RC=1`, ASan-clean (`WRITTEN=100000` on drain).
- Plain build under gdb: `avail_in=34465`; `state->in[0]=0xb3`, `[17]=0x87`,
  `[16384]=0x86`, each equal to the peer's bytes at source offsets 65535,
  65552 and 81919 — peer-chosen content at chosen destinations, one past the
  object.

This upgrades rung 4 from "application-chosen bytes in a harness" to
"peer-chosen bytes in a live loopback server", not to rung 5. Full pins, raw
evidence, failed control configurations and negatives are in
`lab/frontier/zlib2shell/PROVENANCE.md`.

## Independent witness verdict — W144 (2026-11-23 05:06–05:11Z)

Witness replayed from its own clean `git archive` of HEAD (`1d09288`; target
tree unchanged `beab687..HEAD`) with its own builds at a different `/tmp`
source path. Base harness: `REPLAY=1` `run.sh` rc 0 `PASS=30 FAIL=0`, full
`run.sh` rc 0 `PASS=31 FAIL=0`, trace
`28bbacf46cc178ebea825bfc57bcc83564607b4c8a32c52d7531a2d1524d7a89` exactly.
W1: `run_tcp.sh` rc 0 `PASS=14 FAIL=0` twice, trace
`3ae896390ce28d6ec551dbac3e8e6473fd7ae923be9cb7f42762721dbdd78d02` exactly.
Raw ASan: `WRITE of size 34465` in `gz_vacate` at `gzwrite.c:394`, 0 bytes
after the 16384-byte region; fixed pin and 1 MiB drain ASan-clean
`PRINTF_RC=1`; 4 KiB slowdrain also overflows. gdb: `avail_in=34465`, source
base 65535, `state->in[0]=b3`, `[17]=87`, `[16384]=86`, each equal to the
peer's bytes at offsets 65535/65552/81919 (`PEER_BYTE_CHECK=PASS`). Source
bound checked: pinned parent `:234`/`:245-246`/`:386-388`/`:394`; fixed blob
differs by exactly the published +4/-1 hunk. No counterexample. Both claims
ESTABLISHED at the labeled rung-4 scope: no pointer redirect, no control flow,
no command, so rung 5 remains UNKNOWN. No replay owed.

## Rung-5 feasibility check — W2 (2026-11-23 05:2xZ, author-only)

A gdb heap walk on the plain vulnerable TCP server shows the 34465-byte copy
covering `state->out`, zlib's deflate state and the first ~3.8 KiB of the next
64 KiB chunk, replacing heap metadata; the stale source sits in the caller's
100000-byte request buffer at offset 65535. A scan of the pristine destination
range found 0 qwords pointing into executable mappings and 13 heap-like
pointers — no direct call target in this server. Raw gdb output and chunk
walks are in `lab/frontier/zlib2shell/harness/tcp-evidence/layout-*.txt` and
the analysis in `lab/frontier/zlib2shell/PROVENANCE.md`. This is an author-side
negative, not a witness verdict and not evidence against a different
application shape; rung 5 stays UNKNOWN.

## Callable-pointer rewrite attempt — W3 (2026-11-23 06:0xZ, author-only)

A bounded rung-5 attempt added `harness/uv_server.c`, `harness/uv_probe.py`
and `harness/run_uv.sh`. A plant-started loopback gzip server allocates a real
libuv `uv_async_t` after `gz_init()`; a 359400-byte stalled request makes the
stale `gz_vacate()` copy long enough to reach it. gdb readback after the
memmove shows the handle's `data` bytes replaced by `id>a` and its `async_cb`
field replaced by exactly the printed `system@plt` address
(`harness/uv-evidence/callback-rewrite-gdb.txt`). That is a peer-chosen
function pointer in a real heap consumer, beyond the W2 byte-copy result.

The attempt did not reach rung 5: `uv_run()` segfaults inside `libuv.so.1`
before dispatch, no command marker appears, and the same crash occurs when
the handle bytes are preserved verbatim, so collateral heap corruption blocks
this consumer. Fixed build and draining-peer controls are clean (`UV_RAN=1`,
rc 0, no marker); trace hash
`39c477c855862aa4f3fc37c04e81396b859afef79016014a56b4c1c732dd33c6`.
The payload also depends on gdb-derived build-specific heap offsets to keep
zlib's allocator from aborting; it is not a wire-only exploit. Author-side
negative, no witness replay owed. Rung 5 remains UNKNOWN.

## W4 — observed command through real libuv dispatch (2026-11-23 06:2xZ, author-only)

W3 showed a peer-chosen `async_cb` rewrite but died before dispatch. The
crash was collateral heap corruption: the faulting object held random peer
bytes. `harness/capture_uv_snapshot.py` now captures the 293865-byte
pre-memmove destination image under gdb with ASLR disabled, and
`uv_probe.py --snapshot` replays it as request bytes at the stale source
offset, leaving only the chosen command and callback pointer changed.
`bash harness/run_uv_snap.sh` rebuilds from the pin and produces trace hash
`1d0b5122c8f45d6f5a1acdab8da6d4a90c00609c2ae28912e8e9461a3abb8611`
stable across two clean replays; raw output in
`lab/frontier/zlib2shell/harness/uv-snap-evidence/`.

In the vulnerable build the peer's `id>a` and `id>b` both produce `MARKER=1`
with `id` output in the corresponding file, `UV_RAN=1` and rc 0, with no
debugger attached to the exploit run: libuv's own `uv_run()` calls the
rewritten `async_cb`. Fixed build: `MARKER=0`, `PRINTF_RC=1`, `UV_RAN=1`.
Vulnerable with the original callback kept: `MARKER=0`. Vulnerable with ASLR
on: `MARKER=0`, `SERVER_RC=-11`. Vulnerable with a draining peer: no overflow,
`MARKER=0`.

Ceiling: **command execution observed in a live loopback process under
explicit lab conditions** — -no-pie plain build, ASLR off, gdb-captured heap
image replayed by the peer, fixed heap delta and printable `system@plt`.
The peer does not need to invent the command or pointer, but it does need a
memory image unavailable from the wire in this experiment, so this is not a
wire-only exploit. Author-only: independent witness replay is owed before an
ESTABLISHED rung-5 label. The older rung-4 ESTABLISHED claims are unchanged.
