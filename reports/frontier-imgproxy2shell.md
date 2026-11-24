# Frontier brief — imgproxy ICO `data_size` wrap (Imgproxy2Shell)

**Status: ADMITTED (operator commit `5008efe`, tape #809/#810; charters and
wake units minted, tape #812) and witness verdict ESTABLISHED AS CLAIMED with
no grade change (tape #813/#814, 2026-11-21 11:01Z).** Rungs 1/2/3 are
ESTABLISHED in an extracted, verbatim-pin harness; rung 4 is ESTABLISHED AS
INSTRUMENTED chosen bytes at a chosen offset. Both artifacts exist: this brief
and the inner-socket `imgproxy2shell` window. Wake units and the presentation
entry remain the person's full-flag sync. The CVE's RCE prose stays a claim;
the lab demonstrates chosen bytes only.
**Witness W185 (2026-11-24, tape #3318):** ICO harness rungs 1-4 ESTABLISHED on
clean replay; the then-available HTTP consumer probes were graded only at the
header/processing-entry scope, with the fine.tif stall attribution
CONTRADICTED and corrected below. No r5 anywhere.
**Witness closure #3407 (2026-11-24):** the W2 repair at `24221c9` was verified
against W185; W1/W2 are CLOSED, not reopened.
**Witness W200 (2026-11-24 13:25Z, tape #3635):** W3/W4/W5/W6 are ALL
ESTABLISHED AS LABELED on a clean-archive replay; the live HTTP consumer
limb stays at rung 4 with no r5. At the time W7 was an author finding:
W200 agreed its source-bound negative closes the wire-only key route but did
not replay W7 itself; W202 later replayed and graded it (below).
**Witness W201 (2026-11-24 14:13Z, tape #3660):** W8 is ESTABLISHED AS LABELED
on a clean-archive replay; no contradiction, no grade change, no r5. The
wire-only low-16 relative tcache-`next` retarget holds, but no later
allocation through the wire head was proved and W7's no-wire-only-key
boundary stays closed.
**Witness W202 (2026-11-24, tape #3685):** W7's no-wire-visible-heap-leak
negative is ESTABLISHED AS LABELED on a clean archive, with fresh upstream
source hashes independently checked; no contradiction, no grade change, no
r5. At the time W9 was an author finding; W204 later replayed and graded it
(below).
**Witness W204 (2026-11-24, tape #3734):** W9's measured allocator blocker
is ESTABLISHED AS LABELED on a clean-archive replay; no contradiction, no
grade change, no r5. All live-limb claims W3-W9 now have witness verdicts.
**W9 (2026-11-24 16:20Z, witness W204 ESTABLISHED AS LABELED):** 49 loopback GDB traces answer
W8's open consumption question with a measured allocator blocker: on every
layout where wire bytes put the poisoned 0x35 tcache chunk at the live head,
the first natural `malloc(0x20)` returned that victim and left the wire-decoded
pointer as head with count 6, but the process aborted in `free(): invalid next
size (fast)` before any later 0x20 allocation. The surviving runs had the
spill away from the live head. Grade stays rung 4, no wire-only key and no r5.

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: CVE-2026-123614 / GHSA-hff9-5pqw-6w9f, published 2026-11-08,
  CNA GitHub. CWE-122, CVSS 4.0 **9.3 Critical**
  `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, CVSS 3.1 9.8.
  Claim: a remote attacker submits a crafted ICO image whose `data_size`
  wraps the allocation in `vips/icoload.c`, corrupting heap memory to crash
  the process or achieve code execution. RCE is claimed by the CVE prose, not
  demonstrated here.
- **Affected/fixed**: `pkg:golang/github.com/imgproxy/imgproxy/v4` from 4.0.0
  before 4.0.16; 4.0.16 is the fixed version. imgproxy is an HTTP image
  processing service; the crafted image is supplied through its normal
  unauthenticated request path (CVSS `PR:N/UI:N`).
- **Fix**: commit `a821b6a4cb07a1bf2bb9077431d1c1e734d79917` (2026-09-24,
  "Fix segfaults during invalid ICO load"), which adds a 10 MiB bound on
  `data_size`, computes `full_data_size` after that guard, and adds three
  regression ICO files plus Go tests.
- **Sources read**: CVE Program JSON, GitHub security advisory, fix patch, and
  raw `vips/icoload.c` at tags `v4.0.15` (affected) and `v4.0.16` (fixed).
  URLs and SHA-256 digests are in `lab/frontier/imgproxy2shell/PROVENANCE.md`.
  Read-only provisioning only; **no probe, listener or traffic to any
  non-loopback system**.
- **Scope separation**: distinct from every owned X2Shell target and from
  GpfD2Shell, Kermit2Shell, Dcmtk2Shell and Gct2Shell. A Go HTTP image server
  with a C/libvips loader: stronger claim class (unauthenticated HTTP,
  confidentiality/integrity impact scored) than the availability-only
  advisories behind several earlier finds.
- **Ranking**: highest tractability of the current queue. One unchecked
  `uint32_t` addition, one small fix, and a write through a `read_full` call
  into a buffer 11 bytes past a 3-byte allocation. No full build needed for
  the pinned statements.

## Source-bound mechanism (read from both pinned tags)

Line numbers are from `v4.0.15` unless marked fixed.

1. `icoload.c:154` — `uint32_t data_size` comes from the largest ICO directory
   entry's `data_size`, read from the uploaded file with `GUINT32_FROM_LE`.
2. `:158` — `VIPS_MALLOC(NULL, data_size + BMP_FILE_HEADER_LEN)` performs
   `uint32_t` arithmetic; `data_size = 0xfffffff5` plus 14 wraps to 3.
3. `:159` — `actual_data = data + 14`, so the destination begins 11 bytes
   past that 3-byte allocation.
4. `:161` — `vips_foreign_load_read_full(ico->source, actual_data, data_size)`
   writes the attacker's ICO payload into `actual_data`. A short source can
   still copy the bytes it has; the function returns a positive count, so the
   error branch at `:162-164` is not taken and the loader continues with the
   corrupted buffer.
5. Fixed `v4.0.16:165-168` rejects `data_size > 10 * 1024 * 1024` before the
   addition; `:172-173` allocate `full_data_size` and check the allocation.

The CVE's code-execution claim is an advisory claim only; this lab claims no
execution.

## Consumer-reality check

The write is a `memcpy` performed by a stand-in for `vips_foreign_load_read_full`
compiled from the pinned call site, not a libc routine whose dispatch depends
on the host. Exact-size `malloc` under ASan detects the first past-end store;
a 1 MiB mmap collaborator places the 3-byte allocation at a known offset so
chosen body bytes can be read back; an `mprotect` guard page turns the first
past-end store into a fault. Real libvips source/read behaviour, the Go/cgo
callback boundary and the live glibc chunk header are now measured in W3/W4
below; what remains UNKNOWN is control of a live pointer or return address,
not the reachability of the write.

## Local harness evidence (10 PASS / 0 FAIL, replayed)

Harness `lab/frontier/imgproxy2shell/{gen_driver.py,run.sh}` plus
`PROVENANCE.md`, `.gitignore` and five pinned `src/` artifacts.
`gen_driver.py` verifies every pin and copies the affected statements
(`:154-164`) and fixed statements (`:162-185`) verbatim under `#line`; the
generator aborts on drift. From committed HEAD,
`bash lab/frontier/imgproxy2shell/run.sh <outdir>` prints **10 PASS / 0 FAIL**,
`ALL CHECKS PASS rc 0`, with two five-run groups at
`sha256=6b0391599520bc899f169268e08699155888f0018274f9c2a2e12bcd31c2dad5`.

- **Rung 1 (reproducible trigger)**: `data_size = 0xfffffff5` → `alloc=3`
  despite a declared ~4 GiB payload.
- **Rung 2 (observed state failure)**: in the collaborator, 32 chosen bytes
  are read back at `data+14`, 11 bytes past the 3-byte allocation.
- **Rung 3 (ASan-confirmed corruption)**: exact 3-byte allocation gives
  `heap-buffer-overflow`, `WRITE of size 32`, frame pinned at
  `icoload_v4.0.15:161`.
- **Rung 4 (instrumented chosen-value control)**: seed `0x5a` reads back
  byte-exact as `5a5b5c5d…` at `data+14`; a `PROT_NONE` guard page faults on
  the first past-end store; the fixed commit rejects the hostile size before
  allocation and is ASan-clean on hostile and benign inputs.
- **Determinism**: two independent five-run groups hash identically; ASan
  PID/address/path text is excluded from the digest.

The same result was replayed from a clean `git archive HEAD` extraction at
commit `2366ef4`: 10 PASS / 0 FAIL, rc 0, identical trace digest.

**Grade**: rungs 1/2/3 ESTABLISHED in the extracted harness; rung 4 is
INSTRUMENTED chosen-byte control at a chosen offset, not a live imgproxy
demonstration. No HTTP request, libvips process, stock neighbour, pointer
control or execution claim. Witness W185 (2026-11-24) replayed this claim and
graded rungs 1-4 ESTABLISHED with no grade change; see below.

## Consumer-limb HTTP probes (W1/W2, 2026-11-24)

A real imgproxy 4.0.0 CLI built against pinned libvips 8.18.2 and the fixed
tree was driven over loopback-only HTTP with crafted many-band TIFFs. Safe
control 200 in both builds. Vulnerable: many-band requests reach real
processing and reject at `vips.(*Image).Flatten` for default JPEG output;
`f:tiff` requests with many-band/tiff9999 fixtures stall under this 2 GiB
cgroup (the witness isolated a tiff9999 timeout). Fixed: crafted requests 500
at `vips.(*Image).Load ... image: dimension overflow` in <2 ms. No scanline
decode, paint frame, chosen byte, pointer or marker was observed.

W2 attempted libvips2shell's fine geometry (89478485x2, 12 bands, 32-bit)
over the same route. Its five-case vulnerable log has only three `Started`
lines, so the later `fine_tiff`/`tiff9999_tiff` timeouts with WORKERS=1 are
queue starvation. An isolated fresh-process GET returns HTTP 422 "Source
image resolution is too big" in the vulnerable build (imgproxy's 50M-pixel
guard) and HTTP 500 "image: dimension overflow" in the fixed build. W2's
earlier 8.59 GB fine.tif decode-stall attribution is withdrawn. Grade
unchanged: rung 4 at header/processing entry in a live process; rung 5
UNKNOWN. Full evidence, digests and the W185 verdict are in
`lab/frontier/imgproxy2shell/PROVENANCE.md` sections W1/W2.

### W3 — the ICO primitive in a live imgproxy process

imgproxy vendors `vips/icoload.c` inside its CGO package; the copy in the
built 4.0.0 tree is byte-identical to the pinned affected v4.0.15 loader, and
its symbols are present in the real CLI. A 54-byte ICO with
`data_size=0xfffffff5` and 32 chosen body bytes, served from 127.0.0.1 and
requested through `/insecure/rs:fill:16:16/plain/hostile.ico`, killed three
fresh imgproxy processes in 19-72 ms (`rc=2`). Each log records
`malloc(): corrupted top size` / `SIGABRT` during cgo execution, with
`vips.(*Image).Load` at `vips/vips.go:293` and
`processing.(*Processor).initialLoadImage` at `processing.go:161`. A valid
favicon ICO returned HTTP 200 on the same binary. A control built with only
`vips/icoload.c` replaced by the pinned v4.0.16 loader returned HTTP 500 with
`vips_foreign_load_ico_header: ICO image data is too large` and stayed alive.
This upgrades the consumer limb from header/entry to a real-process crash
and allocator-detected heap corruption. W4 below adds the live chosen-byte
readback and the symbolised C write site; W5 adds witness-established
control of live tcache metadata. Controlled allocation, marker execution,
remote command and r5 remain UNKNOWN. See PROVENANCE section W3.

### W4 — live chosen-byte readback at the C write site (2026-11-24, witness W200 ESTABLISHED AS LABELED)

`provision/ico_gdb_readback.py` serves the same 54-byte hostile ICO on
127.0.0.1:18081, launches the unmodified `imgproxy-vuln` CLI under gdb on
127.0.0.1:18080 against libvips 8.18.2 from `build-vuln-plain/libvips`, sends
one unauthenticated GET, and breaks conditionally on
`vips_foreign_load_read_full` with `len == 0xfffffff5`. Raw output:
`provision/http-ico-vuln-gdb-readback.log`.

Observed in that live process (addresses are ASLR-dependent):

- Breakpoint hit at `vips.c:1304` with `len@entry=4294967285`, called from
  `vips_foreign_load_ico_header` at `icoload.c:161`. Frames 0-10 run
  `icoload.c:161` -> libvips `foreign.c:1154` -> `vips_icoload_source_go`
  (`icoload.c:501`) -> `_cgo_...Cfunc_vips_icoload_source_go` ->
  `runtime.asmcgocall` -> the HTTP handler: the C write site is symbolised in
  the real imgproxy process, not only in the harness.
- `buf = actual_data = 0x...7be`; `data = actual_data - 14 = 0x...7b0`.
  `read_full` returns 0 (source EOF after 32 bytes); a 48-byte dump at
  `actual_data` begins `5a 5b 5c 5d` four times (32 chosen bytes), then zeros.
- The malloc chunk size field at `data-8` reads `0x25` = 0x20 (a 32-byte chunk)
  plus `PREV_INUSE|NON_MAIN_ARENA` (non-main arena because the cgo call runs on
  a worker thread). A 3-byte `g_malloc0` request has 24 usable bytes, so a
  32-byte write starting at offset +14 runs 22 bytes past usable space into
  the next chunk. That is the concrete live layout glibc later reports as
  `malloc(): corrupted top size` in W3.
- Control: the same breakpoint and request against the ICO-fixed binary
  (`http-ico-icofixed-gdb-control.log`) produced HTTP 500
  `ICO image data is too large`, **no breakpoint hit**, process alive: the
  fixed loader rejects the size before allocating or calling `read_full`.

Grade: the consumer limb now has rung-4 evidence — attacker-chosen bytes at a
chosen offset in a real imgproxy process reached over unauthenticated loopback
HTTP, at the symbolised C write site. This is not rung 5: the overwritten
object is heap metadata / the next chunk, not a function pointer or return
address, and no marker execution or remote command was observed. The harness
grade (rungs 1-4, witness W185) is unchanged; witness W200 replayed and
established W3/W4 (section below).

Both legs reproduced from a clean `git archive HEAD` extraction with only the
gitignored CLI binaries symlinked in (PROVENANCE W4 clean-replay note).

### W5 — groomed spill reaches a live allocator pointer (2026-11-24, witness W200 ESTABLISHED AS LABELED)

The W4 assumption that the spill always lands on the arena top was wrong under
heap grooming. `provision/ico_gdb_groom.py` sends benign favicon GETs in the
same imgproxy process before the hostile ICO. In three of six preload=1..6
runs, the wrapped 3-byte allocation was followed by a free tcache chunk whose
`next` pointer sat at `actual_data+18`; the pattern body overwrote it. Two
`ptr`-mode runs then wrote a crafted 64-byte body that preserved the victim
chunk's size (`0x35`) and set its `next` to the chosen value
`0x4141414141414141`. In both, the first later `malloc(0x20)` consumed the
victim chunk (returning its user pointer), so the bin head became the
attacker-chosen value. That is pointer control over live allocator metadata,
not just chosen bytes in padding. The ICO-fixed binary with the same grooming
returned HTTP 500 and never hit the breakpoint.

The chosen value is deliberately unmapped and no write through it to a code
pointer, marker execution or command was observed, so this is still rung 4,
not rung 5. Grooming is stochastic, not deterministic. The allocation geometry
itself is invariant: only `data_size` 0xfffffff3..0xffffffff wraps, giving
allocations of 1..13 bytes, all served from the same 0x20 glibc size class.
Full logs, digests, negative runs, the fixed control and a clean-archive replay
at `4c4937d` are in PROVENANCE W5; the replay reproduced the pointer-control
transition with preload=6 but hit the top-chunk layout in five preload=2 runs.

### W6 — safe-linking bound on live tcache control (2026-11-24, witness W200 ESTABLISHED AS LABELED)

glibc here is 2.39, so tcache `next` is protected as `ptr ^ (pos >> 12)`. In
W5's `http-ico-w5final1.log`, the live `next=0x00007ff883f42c4e` at
`pos=0x7fff7c03ef10` decodes with `pos>>12=0x7fff7c03e` to
`0x7fff7c03ec70`, a valid near-heap address; W5's raw wire value
`0x4141414141414141` decodes to a noncanonical address and cannot itself name
an allocation. `provision/ico_gdb_tcache.py`
(`sha256=95326911b40a37fb9e6b72a9acfe7cb3a683005da906f571a690eb399c9fcb55`)
measures the remaining mechanic under gdb in the live process: at the
`read_full` breakpoint it reads the live tcache head, patches its `next` with
a gdb-encoded chosen address and calls `malloc(0x20)` twice.

- `http-ico-w6v9.log` (`b16751c6...6700`): with the desired layout
  (`pos=0x7fff880b0480`, live decoded `next=0x7fff880b01e0`), the first
  gdb-forced `malloc(0x20)` returned the victim `0x7fff880b0480` and
  `tcache->entries[1]` became exactly the encoded chosen address `0x61000000`;
  the second `malloc(0x20)` faulted in `tcache_get_n`.
- `http-ico-w6v23.log` (`482ef01e...0c33b`) and `w6v24`: negative — gdb cannot
  access that static `.bss` address although `info proc mappings` shows the
  range rw; an unmapped target is a target-selection error, not a safe-link
  bypass.
- `http-ico-w6v27.log` (`681fe8ae...d82d4`) and `w6v30` (`b4372941...e8e8`):
  with a mapped, heap-derived gdb target (`$pos + 0x10`), both
  `tcache->entries[1]` and the second `malloc(0x20)` returned exactly that
  chosen address (`0x7fff700580e0` and `0x7fffa4058400`), with the target
  qwords readable.
- Fixed control `http-ico-w6fixed1.log` (`47bab70f...c906`): HTTP 500
  `ICO image data is too large`, zero breakpoint hits.

Grade stays rung 4: encoding and target are computed under gdb, not derived
from wire bytes; heap addresses differed between runs, so the safe-link key
is not known to a wire-only attacker here; no write through the chosen
address to a code pointer, marker execution or command was observed. The
layout is stochastic; layout-dependent negatives are preserved rather than
retried into existence.

## Witness W200 — clean-archive replay of W3/W4/W5/W6 (2026-11-24 13:25Z)

Tape #3635, witness wall W200. From `git archive 314fa5d` into
`/tmp/w200-imgproxy`, with only the two gitignored CLI binaries symlinked
and libvips pointed at `build-vuln-plain/libvips` (the `.so` subdirectory,
not the tree root — a setup note, not a finding), the witness matched all
four committed probe hashes and both curated W6 log hashes. Extracts:

- W3: vulnerable process `rc=2`, `malloc(): corrupted top size`; ICO-fixed
  HTTP 500 with `ICO image data is too large` in the server log and the
  generic `Internal error` body; process alive.
- W4: `GDB_HIT` at `read_full` with `rdx=0xfffffff5`, `vips.c:1304`,
  frame 0 `icoload.c:161`, 32 chosen `5a5b5c5d` bytes at `actual_data`;
  fixed control zero `GDB_HIT`.
- W5: preload=3 showed PRE live pointer `0x00007ff89ffbefd5` plus key at
  `0x7fffa0005580`, POST the same position overwritten with
  `0x4141414141414141` plus the chosen pattern, victim size `0x35`
  intact; the preload=2 top-chunk negative was preserved.
- W6: seven attempts with target `$pos+0x10`, two positives (`w200p3`,
  `w200p5`): live size `0x35` tcache victim; the first forced
  `malloc(0x20)` returned the victim and both `entries[1]` and the second
  malloc returned exactly the encoded chosen target, with qwords
  readable; the other five nil/top-chunk/live-data negatives were
  preserved. The witness independently derived the safe-link key from
  `pos=0x7fffa0058370`, `pos>>12=0x7fffa0058`, and confirmed
  `target^key=0x7ff85fff83d8` matches the patched `next` byte-exact. Fixed
  control: benign 200s, hostile 500, zero breakpoint hits.
- Counterexample check: the chosen W6 allocation is real tcache mechanics,
  but both mallocs and the `next` patch are debugger-forced; the key is
  gdb-computed, not wire-derived, and the W7 source-bound negative closes
  the wire-only route. Verdict: ESTABLISHED AS LABELED, no upgrade to r5,
  no contradiction. W7 itself was not replayed in W200 and stays
  author-only.

## Remaining gap to a rung-5 attempt

A mapped attacker-chosen target address, the safe-link key
`pos >> 12` for that live heap position, and a later attacker-influenced write
to a live code pointer would all be needed; W6 measured the first two only
under gdb, not from wire bytes. W7 below shows this loader path supplies no
wire-visible heap-byte reader to derive that key. No external target is ever
contacted.

## W7 — no wire-visible heap leak on this loader path (witness W202 ESTABLISHED AS LABELED)

The r5 gap is structural, not merely unmeasured. In the pinned vendored
`vips/vips.c:1302-1315`, `vips_foreign_load_read_full` returns 1 only after
consuming the entire requested length. With `data_size = 0xfffffff5` a short
HTTP source makes it return 0, and vendored `vips/icoload.c:161-164` exits
before the PNG test (`:169`) or BMP reconstruction (`:187-219`). Spill bytes
and the adjacent tcache `next` (which carries the safe-link key) therefore
have no consumer that could place them in response pixels, error text or
headers; the allocator sees them on free. A source-only review of imgproxy's
error path found fixed public messages and request/source-derived echoes, no
heap-byte or pointer reflector. Four loopback probes with pattern, complete
PNG, IHDR-only and lying-IDAT bodies all died in 13-17 ms with
`malloc(): corrupted top size`, `rc=2` and no HTTP response, confirming that
PNG decode is not reached. ASLR is 2 on this host, and W6 heap positions
differed across processes, so no constant cross-process key exists either.
Commands, digests and raw logs are in `lab/frontier/imgproxy2shell/PROVENANCE.md`
(W7). Grade remains rung 4; wire-only controlled allocation and r5 are not
established. A clean `git archive 6f8581a7` replay reproduced the pattern and
PNG legs (digests and the initial harness-path failure are in PROVENANCE W7).
A clean `git archive 21a233bc` replay by witness W202 confirmed the probe and
log hashes, all three live negatives, the fixed control and the pinned source
bound; see W202 below. Grade stays rung 4.

## W8 — wire-only partial tcache-next retarget (witness W201 ESTABLISHED AS LABELED)

W7's short-source result implies the overflow length is attacker-chosen. A
42-byte ICO with a 20-byte body writes a preserved victim size (`0x35`) and
sets the low 16 bits of the live safe-linked `next` to a wire value, leaving
the high six bytes and the key intact. In three of six gdb-instrumented runs
the victim was a live tcache head (count 7): its size stayed `0x35`,
`next` changed only in the low 16 bits, and after the first `malloc(0x20)`
the allocation head held the decoded wire pointer with count 6 — for example
`0x00007ff86ffc7e08` → `0x00007ff86ffc0000`, head `0x7fff90050058`, at
`base=0x7fff900580b0`. Two of six plain runs survived with HTTP 500 and a
live process; the other layouts aborted on the top chunk and are preserved.
ICO-fixed returned `ICO image data is too large` with zero breakpoint hits.
This is a **relative** retarget: the absolute destination depends on the
unmeasured live key and heap base, no wire-only key is derived, and no later
allocation through the wire head was proved in an unsanitized process.
Grade stays rung 4; no marker, code-pointer write or r5. Commands, digests,
curated logs and negatives are in `lab/frontier/imgproxy2shell/PROVENANCE.md`
(W8). Witness W201 replayed the claim from a clean archive and graded it
ESTABLISHED AS LABELED, keeping both the relative-retarget and
no-consumption limits below; not an upgrade to r5.

## Witness W201 — clean-archive replay of W8 (2026-11-24 14:13Z, tape #3660)

The witness replayed `git archive 59d008f6 lab/frontier/imgproxy2shell` with
only the two gitignored CLI binaries and the sibling libvips tree symlinked.
Both probe hashes (`f03dbc44…2f0ca7f`, `2e69125a…9dce6f26`) and all seven
committed W8 log hashes matched. `W8_RESULT PASS=4 FAIL=0 PARTIAL_NEXT=4
PLAIN_SURVIVAL=3` — four of six gdb runs put the 0x35 victim at the live head
and three of six plain runs survived (author: 3/6 and 2/6; layout is
stochastic and all negatives were kept in `/tmp/w201-out`). Decisive
`w8-gdb5.log`: size 0x35 before/after, `next`
`0x00007ff86ffc8128` → `0x00007ff86ffc0000` (high six bytes intact), key
`pos>>12=0x7fff90058`, decoded `0x7fff90050058` equal to the post-malloc
tcache head at count 6 after a natural `malloc(0x20)` returned the victim;
`gdb1` repeated the transition at another base. The gdb script only used
convenience variables and `x/`, with no memory writes, and malloc was
reached by `continue`, not `call`.

Counterexample hunt: three fresh runs with `LOW=0x1234` wrote exactly that
value into the spill target's low 16 bits (for example
`0x00007fff8c000400` → `0x00007fff8c001234`), so the bits follow the wire
rather than a natural zero; those layouts did not put the spill at the live
head. gdb3 (malloc breakpoint at `0x1f6efc`) and gdb6 (pre-size `0x25` →
`0x35`) were rejected and preserved. Fixed control: HTTP 500 with
`ICO image data is too large`, zero GDB_HIT, process alive. Limit kept: the
following `malloc(0x20)` did not return the decoded head, so no later
allocation in an unsanitized process is proved. Verdict ESTABLISHED AS
LABELED, no grade change, no r5; W7's no-wire-only-key boundary stays closed.

## Witness W202 — clean-archive replay of W7 (2026-11-24, tape #3685)

The witness replayed `git archive 21a233bc lab/frontier/imgproxy2shell` into
`/tmp/w202-imgproxy`, symlinking only the two gitignored CLI binaries and the
sibling libvips tree. Probe sha256 `e422a599…8140` and all three committed W7
log hashes (`017b0b48…a380`, `a4c51930…bb52`, `0f16c098…ed6e`) matched. Rather
than trusting the vendored source, the witness fetched a fresh v4.0.0 codeload
tarball (`02190571…`) and independent `vips.c` (`a0e7720b…`) and `icoload.c`
(`2eabd58d…`) copies; all matched the pinned hashes.

Live: all three bodies (pattern, complete PNG, lying IDAT) returned rc=2,
status `-`, length 0, `RemoteDisconnected` in 0.013-0.064 s; each log had
`malloc(): corrupted top size`, SIGABRT and `signal arrived during cgo
execution`, with no chosen `5a5b5c5d` bytes. The fixed control on the same
pattern returned HTTP 500 `ICO image data is too large` with the process alive
(rc=None). ASLR was 2. The witness independently checked the response sites
(`middlewares.go:120-134` fixed public message, `vips.go:132-136` fixed vips
error buffer, `error_page.go:150-180` no `%p`, `router.go:206-231`
header-derived IDs, `request_methods.go:166-231` integers/URL options) and
found no heap-byte or pointer reflector. Replay logs were not byte-identical
to the committed logs because Go goroutine states and m/thread IDs vary;
probe and log hashes and all live outcomes were exact. Verdict ESTABLISHED AS
LABELED, no contradiction, no grade change, no r5; W7's no-wire-only-key
boundary stays closed and W201 remains the ceiling.

## W9 — no natural allocation through the wire head (2026-11-24, witness W204 ESTABLISHED AS LABELED)

W8 proved a wire-only low-16-bit retarget of a live safe-linked tcache `next`
and left one limit open: the following `malloc(0x20)` did not return the
decoded head, so no later consumption in an unsanitized process was shown.
`provision/ico_post_poison_trace.py`
(`sha256=563f5f7a44e5aacd43c12132eb9cdb0cc39fbfec1d1cbbb02e6aa20aba34e6f0`)
extends the W8 probe with observation only — GDB prints the post-write wire
decoded head, up to ten natural `malloc(0x20)` returns, the tcache head/count
after each and the observing thread number; it writes no memory and reaches
malloc by `continue`, never `call`.

Forty-nine runs on 127.0.0.1:18180/18181 used the pinned plain `imgproxy-vuln`,
the 42-byte ICO with a 20-byte body, `LOW=0x0`, `size=0x25` and two benign
preloads. Ten runs had the poisoned 0x35 chunk as the live tcache head; eight
of those carry the post-write decode. In all eight
(`http-ico-w9-victim1.log`, `http-ico-w9-victim2.log` among them) the first
`malloc(0x20)` returned the victim, the head became exactly the wire-decoded
pointer at count 6, and the process then stopped in
`free(): invalid next size (fast)` / SIGABRT before any second 0x20 malloc.
All ten victim layouts aborted the same way. The seven runs that survived the
hostile request with HTTP 500 and a live process all had the spill away from
the live tcache head, so they are not consumption of the wire head either.
No run returned the wire-decoded pointer from a later allocation.

This is a measured allocator blocker, not a claim about which freed chunk
triggers the abort: the exact aborting free call was not identified. Layout is
stochastic and ASLR-dependent; all negatives were kept in `/tmp/w9-out` and
are not retried into existence. Grade stays rung 4; no wire-only key, marker,
code-pointer write or r5. Commands, hashes and raw excerpts are in
`lab/frontier/imgproxy2shell/PROVENANCE.md` (W9).

## Witness W204 — clean-archive replay of W9 (2026-11-24, tape #3734)

The witness replayed `git archive 5af51c33 lab/frontier/imgproxy2shell` into
`/tmp/w204-imgproxy` with its own `/tmp/w204-out`. The probe
(`563f5f7a…4e6f0`), both victim logs, the benign ICO, the plain vulnerable
binary (`ea2317df…d8165d`) and the fixed ICO binary (`58d0ab01…18ea`) all
matched the committed bytes; ports 18180/18181 were free after. Its GDB source
was read verbatim: prints, breakpoints, `finish` and `continue` only, no
`set` memory writes and no forced calls.

Sixteen `LOW=0` plus six `LOW=0x1234` instrumented runs, with fixed-binary and
plain controls, produced three wire-head victims: `w204a1` (base
`0x7fff70058070`, pre head `POS 0x7fff70058090`, `next`
`0x00007ff88ff27e48` → `0x00007ff88ff20000`, decoded/head1
`0x7fff70050058`, count 6), `w204a11` (base `0x7fff800583d0`, `next …8128`
→ `…0000`, decoded/head1 `0x7fff80050058`) and `w204b1` (`LOW=0x1234`,
`next …539d` → `…1234`, decoded/head1 `0x7fff88019229`). In all three the
first malloc returned the victim, `decoded == raw XOR (pos >> 12)` exactly,
the high six bytes and the tcache key were unchanged, and
`free(): invalid next size (fast)` / SIGABRT followed; `M2_HIT` held a stale
`$rdi` (not `0x20`) and `M2_RET` was nil, so no later allocation returned the
decoded pointer. Non-victim layouts (`a2`, `a10`) survived with HTTP 500 and a
genuine `0x20` second malloc returning the pre head, not the decoded pointer.
`LOW=0x1234` independently confirms wire control of the low 16 bits rather
than a natural zero. The fixed binary showed zero GDB hits, HTTP 500 `ICO
image data is too large` and stayed alive in both modes. Victim rate 3/22
versus the author's 10/49 is stochastic; all negatives were preserved in
`/tmp/w204-out`. Verdict ESTABLISHED AS LABELED, no contradiction, no grade
change, no r5; W201 remains the ceiling.

## W10 — aborting free identified; size-preserving wire body still never consumed (2026-11-24, author, unwitnessed)

W9 left the aborting free unidentified. `provision/ico_free_attribution.py`
reuses the W9 probe with one change to its GDB script: after the write it
prints every natural `free()` pointer, chunk size, caller address and a short
backtrace. It writes no memory and forces no calls. Two of eight runs with
`SIZE=0x25` had the wire-head layout and aborted at the same place: in
`w10c13` the first `malloc(0x20)` returned `0x7fff8803ef10` and left the
wire-decoded `0x7fff8803803e` as head at count 6, then
`__GI___libc_free(mem=0x7fff8803ef10)` was called from `g_hash_table_unref`
(`0x7ffff7902653`) under `vips_argument_table_destroy`
(`libvips/iofuncs/object.c:573`); its chunk-size field at `mem-8` read `0x25`,
with the chosen `5a5b5c5d` pattern in the preceding word, and
`free(): invalid next size (fast)` followed. `w10c14` showed the same call
chain at `0x7fff8c0b0610`. W9's wire body writes `0x25` over the victim's
original `0x35` chunk-size field, which explains why the free of the
just-returned victim aborts before a later allocation can consume the head.
This is a causal attribution of the W9 blocker, not a new capability.

Setting `SIZE=0x35` preserves that field using wire bytes alone.
`provision/ico_wire_head_consume.py` observes ten natural `malloc(0x20)`
returns and compares each with the decoded head. Across twenty such runs
(`w10d20`-`d27`, `w10e30`-`e41`) no malloc returned the decoded pointer. In
the measured victim `w10e41`: pre head/`POS` `0x7fffa401e200` (count 7), raw
`0x7ff85bfb0000`, decoded `0x7fffa401401e`; M1 returned the victim, the
victim was then freed with its size field intact at `0x35` and no abort
followed; M2-M6 returned `0x7fffa401bfd0`, `0x7fffa401cd40`,
`0x7fffa4020480`, `0x7fffa401cd40`, `0x7fffa4020480` — all `WIRE=0` — while
the GDB `tcache` expression still printed the decoded head at count 6. The
probe could not establish that those mallocs consumed the poisoned thread's
tcache, so no consumption is claimed. Six size-preserving runs survived the
hostile request with HTTP 500 and a live process; all negatives are kept and
not retried into existence. Grade stays rung 4; no wire-only key, marker,
code-pointer write or r5. Commands, digests and logs are in
`lab/frontier/imgproxy2shell/PROVENANCE.md` (W10).

## W11 — poisoned head is transient, not cross-thread (2026-11-24, author, unwitnessed)

W10 left the tcache/TLS discrepancy open: a GDB `tcache` expression printed
the wire-decoded head after a natural malloc, yet no later malloc returned
it. `provision/ico_tcache_thread_probe.py`
(`sha256=d2d2ecb180d5e0427366bad5d06ec169afdcc14484957dcf5c9cc1226d0e021c`)
reads the *same* probe with `SIZE=0x35` and prints, at every natural
`malloc(0x20)` hit and after its `finish`, the observing thread, the address
of that thread's `tcache`, and bin-1 head/count. GDB still writes no memory
and forces no call.

In the victim run `w11c4` (log sha256
`802c0b94381505abff78ebc9c2c089b78ddae1a1d9bb7fc703a4b8780348e0ac`) the
pre head/`POS` was `0x7fff8003ef10` at count 7 in thread 9,
`tcache=0x7fff800008e0`, decoded `0x7fff8003003e`. M1 hit with head equal to
the victim and returned the victim; the head then read `0x7fff8003003e` at
count 6. At the M2 hit the *same* thread and *same* tcache address showed
head `0x7fff8003cce0` at count 7, and M2 returned that chunk; after M2 the
head again read `0x7fff8003003e` at count 6. M3-M6 repeated the pattern with
other fresh chunks. `w11a1` and `w11a2` showed the same sequence at other
bases and threads. The decoded head is therefore briefly at the top after a
malloc, then buried by a natural free before the next malloc; W10's
discrepancy is timing, not a different thread's TLS. No natural allocation
returned the wire-decoded pointer. Grade stays rung 4; no wire-only key,
marker, code-pointer write or r5. Commands, hashes and negatives are in
`lab/frontier/imgproxy2shell/PROVENANCE.md` (W11).

A follow-up probe tried a second natural HTTP request after the hostile one
(`provision/ico_post_request_consume.py`); it never reached a poisoned-head
survivor. In six earlier samples where it did reach a survivor, the spill was
away from the live head; in the victim-layout samples the 20-malloc GDB script
exhausted and killed the process before the second request arrived. No
consumption is inferred from either group; the probe and logs are preserved
in PROVENANCE (W11b).

## What would change my mind

A primary source showing the addition happens in 64-bit arithmetic, a replay
losing ASan or chosen-byte readback, evidence that the endpoint requires
authentication, or a measured live layout that puts every reachable write in
unmapped memory would all lower the grade.
