# Frontier brief: rpm iterReadArchiveNext symlink-size wrap — CVE-2026-95520

Status: **real-consumer lane measured 2026-11-26**. Rung 3 is confirmed in
the pinned function and real rpm; rung 4 is DEMONSTRATED by a crafted RPM
writing 64 chosen bytes past a 1-byte allocation in real `rpm2cpio` and
`rpm2archive`, and on plain `rpm -i` by chosen bytes becoming a live liblua
GC pointer that is dereferenced; under GDB's deterministic layout a chosen
live heap address survives that dereference. A loopback wire delivery path
for the corruption is measured; no chosen pointer, ASLR-stable target or
benign command side effect was observed on it. Witness W312 (#6034) judged
the label honest as a scoped, build-specific claim: the rung-4 live dereference
is tied to the matched embedded-path build, not a fresh-build invariant;
independent replay of the standing real-consumer asks is still open, no r5.

## Claim and scope

- CVE-2026-95520, CNA Red Hat, published 2026-09-29, updated 2026-11-24,
  CWE-787, CVSS 3.1 7.1 (`AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`).
  Sources: `https://www.cve.org/CVERecord?id=CVE-2026-95520`,
  `https://github.com/advisories/ghsa-4hhr-mf67-g46r`,
  Red Hat bug `https://bugzilla.redhat.com/show_bug.cgi?id=2537809`.
- Project: rpm (`rpm-software-management/rpm`), `lib/rpmfi.cc`,
  `iterReadArchiveNext()`. Upstream fix commit
  `5bc8705e0f9a9ffc123fb1c693bdad13de9f7c03` ("Sanity check symlink info
  while iterating an archive (CVE-2026-95520)", author 2026-10-22, commit
  2026-11-02), fixing upstream issue #4347. Vulnerable parent pin
  `c36e855034e604ef20863d541d44ef8c2dbac9e8`. At the provisioned HEAD
  `7c4768a9` (2026-11-25) no tag contains the fix, so pins are commit-level;
  the first release shipping it is UNKNOWN.
- Claimed primitive: a symlink entry whose header declares
  `RPMTAG_LONGFILESIZES = 0xFFFFFFFFFFFFFFFF` makes `lsize + 1` wrap to zero;
  `xmalloc(0)` yields a one-byte region, then the independently controlled
  cpio payload size drives `rpmcpioRead()` to copy attacker-controlled bytes
  past that region. The advisory names `rpm2cpio`, `rpm2archive` and
  `rpm -qlvp` as reachable tools. Real `rpm2cpio` and `rpm2archive` are now
  exercised; plain `rpm -qlvp` is a measured header-only negative.

## Pins and source-bound mechanism

- Byte-exact full-file pins: `pins/rpmfi-vulnerable.cc` (SHA-256
  `51d5d7c96773ca2e00c20e5cba7f049d896300d9f255d0fffadd4193fa7ccf27`) and
  `pins/rpmfi-fixed.cc`
  (`eaca65fdb04b9b8fe7647f2df4aa033d7b40d850500e7c82f9a91a3d87cb376a`).
  Verbatim excerpts: `pins/iter-vulnerable.inc` =
  vulnerable `lib/rpmfi.cc` lines 2182-2254
  (`dd72be1bdb92c68b2d97e38f977344cc5b411c56ee16952e2d1010d8ed49e9ff`);
  `pins/iter-fixed.inc` = fixed lines 2182-2258
  (`0c00ded194575ec9649e3532ff09713faa5e96b36acb10524fb5adc776b92721`).
  Both excerpts include `rpmfiSetFound`, `rpmfiFound` and the whole
  `iterReadArchiveNext()` definition.
- Vulnerable body (excerpt lines 59-61, full file 2240-2242):
  `rpm_loff_t lsize = rpmfilesFSize(fi->files, fx);`
  `char *buf = (char *)xmalloc(lsize + 1);`
  `if (rpmcpioRead(fi->archive, buf, lsize) != lsize) rc = RPMERR_READ_FAILED;`
  `rpm_loff_t` is `uint64_t`, so `UINT64_MAX + 1` wraps to zero exactly.
- Fix hunk adds `const char *link = rpmfilesFLink(fi->files, fx);` and
  `if (link == NULL || lsize != strlen(link)) return RPMERR_BAD_HEADER;`
  before the allocation, relying on the header's 256 MB total size cap.
  The fixed build therefore rejects the attack input at the header check;
  the vulnerable build proceeds to the copy.

**Near-wrap size variants (W316, 2026-11-27 05:1xZ).** Patching only the
symlink's `RPMTAG_LONGFILESIZES` qword in the staged attack package
(`real/attack.rpm`, SHA-256 `068a2a2e…`) produced five inputs. With the ASan
`rpm2cpio` at both pins (`RPM_CONFIGDIR` and `ASAN_OPTIONS` as in
`real/run-real.sh`): `UINT64_MAX` gives vulnerable rc 134 with
`heap-buffer-overflow … WRITE of size 64`, as before;
`UINT64_MAX-1` (rc 134) and `0x7FFFFFFFFFFFFFFF` (rc 134) abort earlier with
`requested allocation size … exceeds maximum supported size` — `lsize`
converts to a huge `size_t`, but `lsize+1` is not zero, so no 1-byte region;
`0x100000000` and the header-matching value `11` both exit rc 1 with no ASan
report. Fixed ASan `rpm2cpio` rejects all five with rc 1 and no ASan report.
This bounds the primitive: `rpmcpioRead()` clamps the requested size against
the cpio entry's remaining bytes (`lib/cpio.cc:442-443`), so a negative
`lsize` is needed to take the full 64-byte copy, and only `lsize = -1` also
wraps the allocation to one byte. No new reader, pointer, marker or r5.
Raw packages, logs and the throwaway patcher: site artifact
`.mishe-tauftauf/artifacts/rpm2shell-w316/`.

## Local evidence

`bash lab/frontier/rpm2shell/run-all.sh`: **28 PASS / 0 FAIL**, rc 0.
GCC and Clang ASan on the verbatim vulnerable body:
`heap-buffer-overflow`, `WRITE of size 64`, `0 bytes after 1-byte region`,
write frame `pins/iter-vulnerable.inc:61` in `iterReadArchiveNext()`; the
1-byte region comes from the stand-in `xmalloc(0)`. A plain build whose
`xmalloc` stand-in allocates 64 physical bytes prints
`CANARY_AFTER=495348452d52504d2121414141414141`: buf+1..buf+10 decode to the
10-byte chosen `ISHE-RPM!!` tail of `MISHE-RPM!!` (byte 0 lands inside the
logical 1-byte region) and buf+11..buf+16 to six chosen `A` filler bytes.
Fixed build on the same attack input is
ASan-clean and returns `RET=-15` (`RPMERR_BAD_HEADER`); safe input with
`lsize = strlen("myscript.sh") = 11` returns `RET=0` and is ASan-clean in
both bodies; the plain fixed build writes no canary.
Stand-ins: header/cpio/file-info accessors, bounded `rpmcpioRead` that copies
the present payload bytes (64) rather than the declared `UINT64_MAX`, and a
caller. The two function bodies are included verbatim; no pinned byte is
edited. Exact hashes, commands and raw logs are in `PROVENANCE.md`.

**Measured negative:** GCC 13.3 at `-O1 -fsanitize=address` inlines
`rpmcpioRead()` into `iterReadArchiveNext()` and reports no overflow
(`RET=-13`); the harness therefore builds ASan binaries at `-O0`, where
GCC and Clang both fire. This is an instrumentation limitation, not a claim
that the vulnerable code is safe at `-O1`.

## Real rpm consumer evidence (2026-11-26)

Built rpm 6.1.90 from vulnerable parent `c36e85503` and fixed commit
`5bc8705e0` with GCC 13.3.0, Debug/`-O0`, `ENABLE_ASAN=ON`, OpenSSL crypto,
and optional host integrations disabled. Local popt/libarchive/libmagic/scdoc
development files were extracted under `lab/frontier/rpm2shell/deps/root`;
no host packages were installed. Workspace-only configure/build logs:
`configure-vuln.log`, `build-vuln.log`, `configure-fixed.log`,
`build-fixed.log`.

`real/consumer.spec` builds an uncompressed package containing
`/opt/linkme -> MISHE-RPM!!`. `real/make-attack.py` locates the symlink's
physical `RPMTAG_LONGFILESIZES` element rather than assuming an offset,
verifies the 11-byte header value and stripped-cpio payload, then emits:

- `safe-newc.rpm`: regular newc payload, header symlink size 11;
- `attack.rpm`: the same v6 header with size `UINT64_MAX`, regular newc
  symlink payload of 64 bytes (`MISHE-RPM!!` + 53 `A` bytes);
- `stripped-attack.rpm`: size `UINT64_MAX` with the original v6 `07070X`
  stripped payload, preserving the non-triggering negative.

Fixture SHA-256: safe seed `620889c2c2abe1d5facbce8254a033912fe071798a52704ed9e0ecf026af1f71`;
attack `068a2a2ec36e6c4baa3d619fa9d84326cff66793ac397a6141fcc5f5f7d18592`;
safe-newc `6369c178d3716c3ef8d8ef906449e942af0d7bb0a946bb2d486e81115d137cbb`;
stripped attack `b78f89b4ed8514606719c15decfce90b5702f9e5fe3e70a38ba2e4bb08b762cc`.

`bash lab/frontier/rpm2shell/real/run-real.sh`: **21 PASS / 0 FAIL**.
Vulnerable `rpm2cpio` and `rpm2archive` both abort under ASan (rc 134) with
`WRITE of size 64`, 0 bytes after a 1-byte region, allocation at
`lib/rpmfi.cc:2241`, copy through `rpmcpioRead()` at `:2242`, and caller
`tools/rpm2archive.cc:249`. Fixed attack returns 1 with no ASan report for
both consumers; vulnerable and fixed safe-newc controls return 0.

The plain Debug consumer was stopped immediately after the real copy;
`real/plain-readback.log` shows all 64 chosen bytes. For deterministic
adjacent-object evidence, `real/adjacent.c` is an LD_PRELOAD lab seam that
intercepts `malloc(1)`, disables tcache, and places a live 64-byte guard
allocation whose first qword points to a marker. `real/plain-layout-groom.log`
shows the 0x51 guard chunk after the 0x21 victim chunk and the marker pointer
at `buf+0x20` changing to `0x4141414141414141`. This is instrumented rung-4
mechanics, not a claim about natural allocator layout. Unmodified sweeps were
variable: `real/plain-layout.log` records one pointer-valued 0x31-chunk hit,
while `real/plain-layout-sweep.log` records a later 12-miss sweep. The natural
object's type and semantic role remain UNKNOWN; no controlled pointer hijack
is claimed.

Measured scope negatives: the default RPM v6 stripped `07070X` payload does
not produce an ASan write on this path; `rpm2cpio` returns 1 after
libarchive reports `Size required (-1)`. Plain `rpm -qlvp --nodigest`
returns 0 and lists the malicious size without entering the archive
iterator. Do not claim the stripped-payload or query-only paths trigger.

### Natural adjacency: downstream dereference negative (2026-11-26)

`bash lab/frontier/rpm2shell/real/run-natural-deref.sh` replays 52 plain,
no-`LD_PRELOAD` GDB runs against real `rpm2cpio`; verified
`NATURAL_DEREF_PASS=52 NATURAL_DEREF_FAIL=0`. All 20 continuations past the
copy exit 1 without a fault: with `lsize = -1`, the actual 64-byte copy can
never equal the declared `UINT64_MAX`, so pinned `lib/rpmfi.cc:2242` sets
`RPMERR_READ_FAILED`, `:2245` frees `buf`, and `:2253` returns; no later code
consumes the adjacent object on this path. Natural adjacency is intermittent:
4/20 pointer-bearing qwords in the verified replay (e.g. before
`ADJacent=0x5555555f3e20`, after `ADJacent=0x4141414141414141`; an earlier
set measured 6/20). A hardware read watchpoint on `buf+0x20` fires in 20/20
runs, including runs where that qword was nil before the copy, and stops at
`rpmfi.cc:2245` one instruction before `call free@plt`; the trigger is not
value-dependent and does not establish a semantic dereference. When
pointer-bearing, the adjacent object is rpm header-import data (tag word
`0x00122204`, count 6, inline `return`, pointer to a header-data region with
strings `sin`, `/dev/n...`), not a vtable or callback slot. Full commands,
samples and interpretation: `lab/frontier/rpm2shell/real/natural-continue/README.md`.

### Controlled copy length scales with the crafted cpio field (2026-11-26 16:45Z)

Pinned `lib/cpio.cc:434-445` computes `size = min((size_t)lsize,
cpio->fileend - cpio->offset)`; with `lsize = -1` the first term is `SIZE_MAX`,
so the cpio entry's declared data length sets the write size. `real/make-attack.py`
now takes `RPM2SHELL_PAYLOAD_LEN` (default 64; CLI unchanged), and
`bash lab/frontier/rpm2shell/real/run-scaled-payload.sh` verified **21 PASS /
0 FAIL**: ASan `WRITE of size 64`, `512` and `4096`, each 0 bytes after the
1-byte region with the write frame `iterReadArchiveNext` at `rpmfi.cc:2242`,
through both `rpm2cpio` and `rpm2archive` invocations; the fixed build rejects
the 4096-byte package with rc 1 and no ASan report; the safe control is rc 0
and ASan-clean. In this build `tools/rpm2cpio` is a symlink to `rpm2archive`
in both vulnerable builds, so those two invocations exercise the same consumer
binary — not two independent implementations.

Plain `rpm2cpio` still exits 1 without a fault at all three lengths, so a
larger overwrite alone produces no semantic dereference on this path. Plain
GDB (`real/scaled/readback-4096.gdb`) prints `LSIZE=-1`, `MISHE-RPM!!` at
`buf` and `0x4141414141414141` at `buf+4088`: chosen bytes reach the end of
the 4096-byte copy. An earlier GDB run with a wrong relative `RPM_CONFIGDIR`
faulted in `tvsub` with `btv=0x4141414141414141`; rerunning with the absolute
config exited 1 with no fault, so that crash is a bad-config artifact and is
not claimed. Grade unchanged: rung 4 DEMONSTRATED with attacker-chosen length
and bytes; natural pointer control and downstream dereference remain UNKNOWN;
no r5.

### Independent consumer: real `rpm -i` faults naturally (2026-11-26 17:00Z)

`tools/rpm2cpio` is a symlink to `rpm2archive` in these builds, so the archive
iterator was also exercised through the install (`fsm`) path. Source mapping
of the pinned tree found four archive-reader construction sites
(`tools/rpm2archive.cc:247`, `lib/fsm.cc:865`, `sign/rpmsignverity.cc:141-142`,
`python/rpmfiles-py.c:507`); every caller stops on negative
`RPMERR_READ_FAILED`, and the two wrapper iterators use bounds-checked
`rpmfilesFLinks()` with negative `fx`. That is source reasoning, not runtime
proof for all four consumers.

Of those four sites, only two consumers are reachable in these builds. The
verity signer is unavailable: `build-vuln-asan/tools/rpmsign --addverity`
returns `unknown option` (rc 1), and the fixed build has no `rpmsign` binary.
No built Python `rpm` module exists under `install-vuln`. The two measured
consumers remain `rpm2archive`/`rpm2cpio` (one binary, not two) and `rpm -i`.
An unmodified `run-real.sh` replay at HEAD `02808d23` (2026-11-27 02:10Z)
returned 21 PASS / 0 FAIL; no grade change, no witness verdict in chat through
#5989.

`real/relocate-install.py` copies the existing fixtures with `/opt/` → `/tmp/`
(equal-length header and cpio names, so no tag offset changes) and derives
`real/install/attack-reloc.rpm`, `attack-zero-reloc.rpm` (53 zero filler
bytes), `safe-reloc.rpm` and `short-read-reloc.rpm` (declared symlink size 64
with only 11 payload bytes: the same short-read error without wrap or
overflow). `bash lab/frontier/rpm2shell/real/run-install-consumer.sh`:
**14 PASS / 0 FAIL**. Vulnerable ASan `rpm -i --dbpath <tmp>` aborts rc 134
with `WRITE of size 64`, 0 bytes after the 1-byte region, write frame
`iterReadArchiveNext` at `rpmfi.cc:2242` through `rpmfiNext` at `:867`; fixed
ASan rc 1 and ASan-clean. Vulnerable plain `rpm -i` faults 3/3 with rc 139;
GDB places the fault in `liblua5.2.so.0` from `rpmluaFree`
(`rpmio/rpmlua.cc:153`) ← `rpmFreeRpmrc` ← `rpmcliFini` ← `main`
(`tools/rpm.cc:317`). Manual repeats before the runner measured A filler
5/5 rc 139, B filler 3/3 rc 139, zero filler 3/3 rc 1 and short-read 3/3
rc 1; the runner repeats A 3/3 and zero/short-read 2/2 each. Chosen payload
bytes therefore decide whether the *unmodified plain* install process faults
at teardown — no `LD_PRELOAD`, allocator seam or debugger-forced execution.
Safe-newc and stripped controls also return 1 without a fault.
At teardown the chosen bytes become a live GC pointer (next subsection), so
this is not merely a value-independent crash. Valid-target redirection and
command execution are not demonstrated; loopback wire delivery is measured
later in this report. Install uses
a private `--dbpath` and four guarded, cleaned `/tmp` names; no other
filesystem location is written.

### Chosen bytes become a dereferenced liblua GC pointer (2026-11-26 17:30Z)

`bash lab/frontier/rpm2shell/real/run-gc-pointer.sh` (8 hard PASS / 0 FAIL,
plus the layout-dependent V case below) runs
the plain vulnerable `rpm -i` under GDB with no `LD_PRELOAD` and no injected
call. The pinned post-copy breakpoint at `lib/rpmfi.cc:2243` prints
`COPY_BUF=0x5555555a8600 NEXT_ADDR=0x5555555a8620
NEXT_AFTER=0x4141414141414141`: the 64-byte write covers the first qword of
a naturally adjacent live object at `buf+0x20`. A breakpoint at
`liblua5.2.so.0` offset `0xe9a6` (`lua_resume+0x206`, the GC-list visit
`movzbl 0x9(%r14),%r13d`) records the last visited GCObject addresses. It
observes `CHOSEN_PTR=0x4141414141414141 PREV_OBJ=0x5555555a8620
NEXT_ADDR=0x5555555a8620 MATCH=1`: the object visited immediately before the
chosen value is exactly the overwritten object. `%r14` and `%rdx` hold the
chosen value; stepping one instruction faults at an address derived from
that value, with backtrace `liblua5.2` ← `rpmluaFree`
(`rpmio/rpmlua.cc:153`) ← `rpmFreeRpmrc` ← `rpmcliFini` ← `main`. Replacing
the filler with `B` produces the same chain with `0x4242424242424242`.
A third fixture writes the little-endian address `0x5555555f54a0` (a live
GCObject in this deterministic GDB layout) into the same qword: the walk
still reaches the chosen pointer with `MATCH=1`, and the `movzbl 0x9(%r14)`
dereference succeeds without a fault. The same bytes in a plain ASLR
process fault with rc 139, so the valid target is a lab-layout fact, not an
ASLR-stable one. Zero filler and the same-error short-read fixture exit 1
without a fault, and the fixed ASan build rejects the attack (rc 1,
ASan-clean). The overwritten object is a liblua collectable whose first
qword is its `next` pointer; chosen bytes therefore replace a live pointer
that liblua dereferences during teardown. A second chosen dereference at a
chosen valid target and any command remain UNKNOWN/NO; loopback wire
delivery is measured later in this report.
Evidence: `real/gc-pointer/{A,B,V}.log`, `real/gc-pointer.gdb`.
Replay note (2026-11-26 18:40Z): the V fixture's fixed address is
layout-dependent. GDB's heap layout varies across runs even with ASLR
disabled, so a replay saw `PREV_OBJ=0x5555555fd920 NEXT_ADDR=0x5555555a83e0
MATCH=0` instead of the original hit. `run-gc-pointer.sh` now discovers a
live GCObject in the current layout with `gc-pointer/discover.gdb`, writes
that address into the same fixture, and reports V as `INFO` when the layout
shifts; A/B and the plain/fixed controls remain hard assertions (8 PASS /
0 FAIL on every replay, 10 PASS when V aligns). The valid-target hit stays
a lab-layout observation, not an ASLR-stable target.

Clean-archive caveat (2026-11-26 18:48Z, superseded as a replay blocker):
replaying the runners from `git archive HEAD` into a long `/tmp` checkout
path (with workspace-only builds, source tree and config symlinked in)
returned `GC_POINTER_PASS=2 / FAIL=6` and
`INSTALL_CONSUMER_PASS=13 / FAIL=1`: A/B lost `MATCH=1`, and plain install
aborted in glibc (rc 134) instead of faulting in liblua. The 18:54Z probe
isolated the cause: the exact `RPM_CONFIGDIR` string length changes the
teardown heap adjacency. An 88-character checkout with its default config
failed `GC_POINTER` 6 PASS / 2 FAIL in 8/8 runs; pointing the same runner at
an 18-character symlink to the same config returned 0 FAIL in all replays,
while a 27-character symlink still failed 5 PASS / 3 FAIL. A 56-character
clean archive and the 64-character worktree already passed. No
clean-archive provisioning defect was found; the deterministic ASan WRITE
checks (`run-real.sh`, `run-scaled-payload.sh`) never depended on this
layout.

Replay repair (2026-11-26 19:14Z): both `real/run-gc-pointer.sh` and
`real/run-install-consumer.sh` now create an 18-character symlink to the
same vulnerable config with `mktemp`, use it for every vulnerable `rpm -i`
invocation (including GDB's `set environment`), and remove it on EXIT via a
trap separate from `fresh()`'s cleanup. Package bytes, binaries, fixtures,
allocation site and controls are unchanged; V stays informational when a
live target does not align. Author verification: 18 consecutive
`run-gc-pointer.sh` replays (six each from the 64-character worktree, the
56-character clean archive and the 88-character checkout) returned 0 FAIL
(10 PASS / 0 FAIL in three runs, 8 PASS / 0 FAIL otherwise), and all three
checkouts returned `INSTALL_CONSUMER_PASS=14 INSTALL_CONSUMER_FAIL=0`.
Grade stays rung 4 author-DEMONSTRATED with the layout limitation attached;
independent witness replay of this lane is still pending.

Clean archive of the repaired commit `54d94b6e` was replayed at 19:15Z with
workspace-only symlinks: runner hashes matched PROVENANCE,
`GC_POINTER_PASS=8 GC_POINTER_FAIL=0` and
`INSTALL_CONSUMER_PASS=14 INSTALL_CONSUMER_FAIL=0`, rc 0. Replay from a short
clean archive path is therefore supported again; the earlier caveat stands
only as the measured 88-character-path negative.

### Measured ASLR ceiling (2026-11-26 18:04Z)

`bash lab/frontier/rpm2shell/real/run-aslr-ceiling.sh` replays **8 PASS /
0 FAIL** in the worktree and from a clean `git archive c2cc89b3` (prebuilt
workspace trees and the install fixture symlinked in). It bounds the
remaining pointer-redirection question. With
GDB's `set disable-randomization off` (GDB only observes; no forced call),
the qword at `buf+0x20` is `NEXT=(nil)` immediately before the real
`rpmcpioRead()` copy and `0x4141414141414141` immediately after it
(`real/aslr-ceiling/pre-copy.log`). There is therefore no ASLR-random
heap pointer whose high bytes a short partial overwrite could preserve:
writing only the low byte with `RPM2SHELL_PAYLOAD_LEN=33` instead aborts
in glibc (`double free or corruption (out)`, rc 134, 3/3) before liblua
walks the pointer; the fixed build rejects that package with rc 1 and no
ASan report. A full eight-byte write of the fixed vsyscall address
`0xffffffffff600000` faults in 3/3 plain ASLR runs (rc 139): on this
6.8.0 kernel the page is `--xp`, so even the first `movzbl 0x9(%r14)`
read faults. No package-controlled state supplies an ASLR-stable live
GCObject address in these runs. This is a measured negative, not a claim
that no other consumer or layout could offer a target; grade stays rung 4
author-layout DEMONSTRATED with no command or r5.

### Live GCObjects in the copy window: partial-overwrite ceiling (2026-11-26 18:24Z)

`bash lab/frontier/rpm2shell/real/run-aslr-window.sh` returned **9 PASS /
0 FAIL**. With ASLR enabled (GDB only observes, no forced call), the probe
snapshots the 4096-byte window at `rpmcpioRead()` entry and records every
later visit at `lua_resume+0x206` — the list step `mov (%r14),%r14` followed
by `movzbl 0x9(%r14),%r13d`. Each of three runs found 78 distinct visited
qword offsets inside the window: live liblua objects *are* naturally
adjacent under ASLR, so adjacency alone is not the missing piece.

The partial-overwrite route is nevertheless closed on this host. For a
low-byte write to redirect a live `next` pointer onto bytes the package
controls, a visited offset `K` must hold a canonical pointer
`buf + delta` with `0 < delta < K` and a reachable 256-byte block; across
13 sampled ASLR layouts, **zero** candidates meet that condition. At
safe lengths the canonical low-offset pointers point outside the window
(or are nil), and the in-window pointers sit at offsets that require
writes of 1185 bytes or more. A 289-byte package write still reaches the
natural liblua teardown fault (2/2 rc 139), but a 1377-byte write aborts
in glibc with `double free or corruption (out)` (2/2 rc 134) before any GC
walk. The fixed build rejects the 1377-byte package with rc 1 and no ASan
report. No chosen ASLR-stable target or command; loopback wire delivery is
measured later in this report and yields no r5. The grade stays rung 4
author-layout DEMONSTRATED with this ceiling attached. Artifacts:
`lab/frontier/rpm2shell/real/aslr-window/{probe.gdb,probe-1.log,len289-1.log,len1377-1.log,fixed-len1377.log}`.

### Redirect candidates beyond the 289-byte bound (2026-11-26 18:43Z)

The earlier survey called writes of 1185 bytes or more unreachable because
`RPM2SHELL_PAYLOAD_LEN=1377` aborts in glibc. That bound was too coarse:
plain vulnerable `rpm -i` sweeps show the abort is not monotonic — 289,
768, 1024, 1152, 1216, 1248, 1280, 1300, 1320, 1344, 1352, 1360, 1376,
1380, 1416, 1424 and 1448 bytes reach the natural liblua SIGSEGV, while
512, 1368, 1384, 1392, 1400, 1432, 1440, 1441, 1456, 1472, 1500, 1552
and 1664 abort with `double free or corruption (out)`. Ten repeats at 1201
bytes gave 6 faults / 4 aborts; 1441 and 1448 bytes aborted 10/10 each.

Ten fresh ASLR-enabled layout surveys (52 visited GC offsets each) found
low-byte redirect candidates that the old `K <= 0x121` bound excluded:
`buf+0x5a0` (1440) holds a `next` pointer to `buf+0x220` in **10/10**
layouts, and `buf+0x750` (1872) to `buf+0x510` in 10/10; a candidate at
`buf+0x4b0` (1200) → `buf+0x140` appeared in 1/10. A one-byte write at
`buf+0x5a0` would preserve the pointer's high bytes and land on a
controlled fake GCObject at `buf+0x200`. It is unreachable here: a 1441-byte
write aborts in glibc 10/10 plain runs, and a GDB run with ASLR on logged
`Program received signal SIGABRT`, `VISITS=589`, `IN_WINDOW=0` — no GC
visit inside the controlled window before the abort. Rewriting the
corrupted chunk-size qwords at `buf+0x18`, or every `buf+0x18+0x10k` size
field up to `0x300`, with plausible values left 5/5 aborts at 1441 bytes.
No chosen ASLR-stable target or command; grade unchanged (loopback wire
delivery is measured later in this report and is not r5).

## Witness replay (W238, 2026-11-26)

ESTABLISHED AS LABELED. `bash lab/frontier/rpm2shell/run-witness.sh` from the
worktree and from a clean `git archive 815a1b0a lab/frontier/rpm2shell` (wrapper
byte-identical, sha256 `52340605…d49d8`) each returned `WITNESS REPLAY PASS`,
four pins exact, `TOTAL: 28 PASS / 0 FAIL`, rc 0. Independently rehashed both
raw upstream `lib/rpmfi.cc` blobs at `c36e85503` and `5bc8705e0` — full-file
and `sed -n '2182,2254p'` / `'2182,2258p'` excerpt hashes all match the pins.
GCC and Clang ASan -O0 logs show `WRITE of size 64`, 0 bytes after the
1-byte region, write frame `iterReadArchiveNext pins/iter-vulnerable.inc:61`
and allocation frame `:60`; fixed attack `RET=-15`, both safe runs `RET=0`,
plain attack `RET=-13` with the canary hex above. The claim's `-O1` negative
was reproduced independently: GCC 13.3.0 `-O1 -fsanitize=address` exits 0
with `RET=-13` and no report.
At W238 time there was no real rpm build, crafted package, wire input,
pointer, command or r5; the real-consumer lane above is later work and is
independently verified by the W314 verdict below. Full W238 detail:
`.mishe-tauftauf/artifacts/witness-w238-rpm2shell/detail.md`.

## Grade and tractability

- **Rung 3:** GCC and Clang ASan-confirmed heap OOB WRITE in the verbatim
  pinned function, plus real rpm `rpm2cpio` and `rpm2archive` WRITE reports
  with fixed and safe-input controls.
- **Rung 4 DEMONSTRATED:** 64 chosen bytes past a real 1-byte allocation;
  plain GDB observes the bytes and a lab-groomed live pointer-bearing
  allocation overwritten by chosen `A` bytes. On the independent `rpm -i`
  path, chosen filler bytes decide whether the unmodified plain process
  faults at teardown (`A`/`B` rc 139, zero/short-read rc 1), and GDB traces
  the chosen qword into a live liblua GC pointer that is dereferenced. A
  chosen live GCObject address survives that dereference under GDB's
  ASLR-disabled layout; the same bytes fault (rc 139) in a plain ASLR
  process. Under `setarch -R` the chosen-pointer fault also reproduces in
  a plain no-debugger process, but no live-target address redirection
  survives there. In the default PIE build an ASLR-stable target remains
  UNKNOWN; in a non-PIE build a chosen fixed `.bss` address is walked by
  liblua under ASLR (section below), but it is only a terminating object.
  No useful live-object redirect, command or command side effect is
  controlled. No natural semantic dereference was seen in 52 plain
  `rpm2cpio` runs (above); this dereference is on `rpm -i` only.
- **Not rung 5:** a loopback-only HTTP wire delivery path does carry the
  crafted package into real `rpm -i` (`run-wire-consumer.sh`, below), but
  it yields no chosen pointer, no ASLR-stable target redirection, no
  command and no observed command side effect. The non-PIE fixed-address
  terminator (below) is not a command path. Wire delivery is not r5.

Next experiment: a chosen fixed address whose object fields are also
controlled would be needed for a useful redirect; the package-only partial
overwrite, fixed-address terminator, high-byte short-write, layout sweeps
and second-consumer routes were measured and bounded above. No command
execution without a live target and benign side effect. Keep the allocator
instrumentation and stripped/query negatives attached to any broader claim.

### Fresh-build clean-archive replay (2026-11-26 20:29–20:54Z)

`real/run-real-witness.sh` rebuilt all three rpm binaries from the pinned
git trees in a clean archive and ran the four grade-carrying runners. The
source-level claim replays: `run-real.sh` 21 PASS / 0 FAIL and
`run-scaled-payload.sh` 21 PASS / 0 FAIL, with fresh ASan WRITEs of 64/512/
4096 bytes and clean fixed/safe controls. The two `rpm -i` layout
assertions did **not** replay on those fresh binaries:
`run-install-consumer.sh` returned 13 PASS / 1 FAIL (safe control rc 0,
author layout rc 1), and `run-gc-pointer.sh` returned 6 PASS / 2 FAIL
(B's chosen qword dereference and adjacency pass; A's `CHOSEN_PTR` chain
does not align). Fresh builds embed different debug paths, so heap layout
is a different lab condition. Rung 4 is therefore **author-layout
DEMONSTRATED**, not a layout-independent replay claim; the fresh-build
negative is preserved in `lab/frontier/rpm2shell/PROVENANCE.md`. Grade is
unchanged in the committed layout; the independent witness verdict was
UNKNOWN at that time (see W314 verdict below).

A second end-to-end wrapper run at 20:57–20:59Z (fresh rebuild again)
returned `WITNESS_REAL_TOTAL PASS=60 FAIL=4`: scaled payloads again 21 / 0,
but the pointer/groom/control failures moved — A and B pointer chains then
passed, while the lab-groomed adjacent-pointer check and the zero/safe
control statuses failed. Across both fresh replays only the ASan WRITE and
scaled-length checks were invariant; every pointer-chain, groom and
zero/safe assertion varied with heap layout.

### Information-leak probe (2026-11-26 21:24–21:29Z)

The pinned `lib/rpmvs.cc:206-209` `%p` diagnostic does disclose a heap
address from a real plain `rpm -i`: a 64-character signature digest tag 273
truncated to `5\0` makes rpm print `package tag 273: invalid data 0x… (1)`
and exit 1. Fresh runs gave different low bits (`0x5c686932fe28`,
`0x5f92259f8e28`, `0x55b3bab7fe38`, plus earlier samples), so the value is
ASLR-random. Truncating a main-header digest string instead gives
`hdr load: BAD`, and a two-package `rpm -i` verifies both packages before
installing either, so the disclosure cannot be fed back into the crafted
package in this consumer. No delta to the cpio buffer or GC object was
measured; grade unchanged, no command or r5. Evidence and hashes in
`lab/frontier/rpm2shell/PROVENANCE.md` and `real/leak-probe/`.

### Debugger-free ASLR-off run (2026-11-26 22:36–22:44Z)

`real/run-setarch-nogdb.sh` disables ASLR with `setarch -R` and measures
unmodified vulnerable `rpm -i` with no debugger attached: three
wild-chosen-pointer runs rc 139, two safe runs rc 1, fixed ASan rc 1 and
clean; 6 PASS / 0 FAIL in two in-tree runs. The same fixture, binary and
argument lengths under GDB show `MATCH=1` for `buf+0x20` and the chosen
qword visited as a live liblua GC object at `liblua5.2.so.0:0xe9a6`, so the
debugger-free fault is the chosen-byte pointer dereference, not an
unrelated crash. Attempting a *valid* chosen target from GDB's
discovery layout failed in all six plain ASLR-off runs (rc 134/139). The lab
condition and grade stay rung 4 author-layout DEMONSTRATED, with no
ASLR-stable target in that PIE layout, no command and no r5.
Evidence and hashes: `lab/frontier/rpm2shell/PROVENANCE.md` and
`real/setarch-nogdb/`.

### Non-PIE fixed-address GC target (2026-11-27 02:2xZ)

`real/run-nopie-target.sh` changes only the build configuration: the pinned
vulnerable rpm is compiled with `-fno-pie -no-pie` (`file` reports an ELF
executable, not PIE) and the 64-byte crafted payload puts the fixed `.bss`
address `0x4063a0` little-endian at offset 32, i.e. the qword the copy writes
at `buf+0x20`. With ASLR active, observer-only GDB reports
`NEXT_AFTER=0x4063a0` and `CHOSEN_PTR=0x4063a0 ... MATCH=1` at the liblua GC
visit: the chosen fixed address is the natural adjacency and is walked as a
live GCObject. Ten unmodified plain installs with that fixture exit rc 1
(normal cpio failure text); five with A filler exit rc 139; the fixed ASan
build exits rc 1 with no report. `NOPIE_TARGET_PASS=13 NOPIE_TARGET_FAIL=0`
rc 0 both in-tree and from a clean `git archive cd28c444`, with the runner
byte-identical. The chosen `.bss` qword is zero, so the walk terminates:
this is a chosen ASLR-stable address reaching a real semantic dereference,
not control of a useful live object, code pointer, command or side effect.
It does not change the overall grade or the default PIE ceiling above.
Evidence and hashes: PROVENANCE section W307 and `real/nopie/`.

**Fresh-build boundary (W309, 02:58Z).** Rebuilding the vulnerable non-PIE
binary from the pinned parent in a clean archive keeps the chosen symbol
(`nm` reports `0x4063a0 B rpmQVKArgs@LIBRPM_6.2`) and the copy-site value
(`NEXT_AFTER=0x4063a0`), and 5/5 fixed-target installs exit rc 1 with a clean
fixed ASan control. The live GC assertion does not survive the rebuild: four
runs gave 9/4, 11/2, 12/1 and 10/3 PASS/FAIL, A filler faulted only 2/5, 3/5,
4/5 and 3/5 times, and two runs never printed `CHOSEN_PTR ... MATCH=1`. In a
binary/path crossover the author binary stayed 13/0 in 4/4 runs while the
fresh binary failed in 8/8, so the divergence tracks the compiled binary,
not checkout path, config or ASLR noise. The reproducible datum is the chosen
fixed-address write plus the vulnerable/fixed/safe controls, not the semantic
dereference. Detail and hashes: PROVENANCE section W309.

**Embedded-path length explains W309 (W310, 03:2xZ).** Two fresh builds of
the same pinned parent used the same source tree, deps, cmake flags and
runner; only the absolute `/tmp` build/source/prefix paths differed. One tree
was constructed with every embedded path the same *length* as the author
checkout's paths, the other with short paths. Both binaries are non-PIE and
place the chosen qword at `0x4063a0`; the matched-path binary replayed
`NOPIE_TARGET_PASS=13 NOPIE_TARGET_FAIL=0` in 4/4 runs with 5/5 A-filler
faults and `CHOSEN_PTR ... MATCH=1`, while the short-path binary failed in
4/4 runs (8/5, 9/4, 10/3, 9/4), with A-filler faults only 0/5, 1/5, 3/5,
1/5 and one run missing the GC visit. Binary hashes:
`8c2408f3…` (matched) and `ccc96564…` (short). Since the matched tree uses
different path *content* at identical lengths, the compile-time variable is
the embedded path length/resulting static layout, not a source or harness
change. `real/run-pathlen-control.sh` builds and compares both trees; raw
logs live under `.mishe-tauftauf/artifacts/rpm2shell-w310/`. This restores
fresh-build reproducibility of the rung-4 GC dereference datum under the
original path geometry, but the target is still a zero `.bss` qword: no
useful object, code pointer, command or side effect, and no grade change.
Detail and hashes: PROVENANCE section W310.

A fixed-address fake-object survey (PROVENANCE W310) found no static object
in this non-PIE build whose Lua tag byte and `next` pointer both form a
usable GCObject chain; the chosen `.bss` target's walk therefore terminates.
The chosen address is `rpmQVKArgs` (`lib/poptQV.cc:15`,
`include/rpm/rpmcli.h:173-183`): its leading qword is CLI-set
`qva_source`/`qva_sourceCount`, not a package-controlled pointer, and its
function-pointer fields start at offset 24, past the terminating qword.
The useful ASLR-stable target stays UNKNOWN.

A later relaxed rescan (W314) removed the W310 chain requirement and checked
the whole writable image for a *terminal* static GCObject, including the byte
at `object+9` that the real GC visit reads. There are zero tagged addresses
at `+9` and four malformed ones at `+8`; none has a valid `next`, metatable
or function-pointer field. No fixed address reachable by the chosen write
can trigger a GC callback, so the useful ASLR-stable target remains UNKNOWN
(PROVENANCE W314).

**Witness label verdict (W312, chat #6034, 03:30Z).** The witness read #6017
with the W310 path-length isolation and ruled: the label is honest as a
scoped, build-specific claim; rung 3 pinned verbatim (chosen qword at
`0x4063a0` under normal ASLR with vulnerable/fixed/safe controls) is
fresh-build reproducible, but rung 4 author-layout DEMONSTRATED is not a
fresh-build invariant and must be stated as tied to the matched
embedded-path build. No useful object, code pointer, command or side effect;
NO r5. This verdict covers the *label only*: the witness has not replayed
the standing real-consumer asks #5630/#5669/#5729, so that acceptance stays
UNKNOWN/open. The grade wording above is therefore read with that qualifier.

### Witness replay (W314, 2026-11-27 04:14–04:15Z) — real consumers

ESTABLISHED AS LABELED; no grade change, NO r5. This closes the standing
real-consumer asks #5630 / #5669 / #5729 / #5731 at the labeled scope. All
four runner sha256 pins matched (`run-real.sh` `1ba873e6…`,
`run-scaled-payload.sh` `d0540006…`, `run-install-consumer.sh` `79f2784b…`,
`run-gc-pointer.sh` `e8e4b5f8…`), as did the vulnerable/fixed source and
excerpt pins. The witness ran the four unmodified runners from the mandated
shared worktree path `lab/frontier/rpm2shell/real`:

| runner | rc | counts |
| --- | --- | --- |
| `bash run-real.sh` | 0 | `REAL_CONSUMER_PASS=21 REAL_CONSUMER_FAIL=0` |
| `bash run-scaled-payload.sh` | 0 | `SCALED_PAYLOAD_PASS=21 SCALED_PAYLOAD_FAIL=0` |
| `bash run-install-consumer.sh` | 0 | `INSTALL_CONSUMER_PASS=14 INSTALL_CONSUMER_FAIL=0` |
| `bash run-gc-pointer.sh` | 0 | `GC_POINTER_PASS=10 GC_POINTER_FAIL=0`, zero INFO (V aligned) |

Substantively, not just counters: in those replays ASan `WRITE of size 64`, zero bytes
after the 1-byte region at `rpmfi.cc:2242` in `rpm2cpio` and `rpm2archive`,
with fixed attack rc 1 ASan-clean and all safe controls rc 0; scaled
`WRITE of size 64/512/4096`; plain `rpm -i` SIGSEGV in `liblua5.2.so.0` via
`rpmluaFree` (`rpmio/rpmlua.cc:153`); A/B/V `CHOSEN_PTR ... MATCH=1` at a
real liblua GC visit (`lua_resume+0x206`, `movzbl 0x9(%r14)`), with `stepi`
faulting on the chosen pointer — not a debugger-forced call.

Qualifier preserved by the witness: runners 1-2 consume the prebuilt
matched-layout worktree binaries rather than rebuilding from pinned trees;
the fresh-build negative (13/1 and 6/2, PROVENANCE W309/W310) remains. Rung
4 here is author-layout DEMONSTRATED, not a fresh-build invariant. No useful
object, code pointer, marker, command, side effect or wire path; no chosen
address dereference of a remote-controlled value. Detail:
`.mishe-tauftauf/artifacts/witness-w314-rpm2shell/detail.md`.

### Loopback wire delivery (2026-11-26 22:56Z)

`real/run-wire-consumer.sh` serves the crafted package from a
loopback-only Python HTTP server and passes the URL to a real `rpm -i`,
which fetches it through its own `%_urlhelper` (curl). Final result is
11 PASS / 0 FAIL both in-tree and from a clean git archive in which all
three binaries were rebuilt from the pins: vulnerable ASan rc 134 with the
same `WRITE of size 64` in `iterReadArchiveNext` at `rpmfi.cc:2242`, fixed
rc 1 and ASan-clean, safe rc 0/1 depending on local install state and
ASan-clean, zero/short fixtures rc 1, and a closed-port URL rc 1 clean.
The plain vulnerable attack rc is an observation (139 in the author layout,
1 in one clean-archive run), not an assertion. The server log records HTTP
200 GETs for all fixtures. This is a measured remote *delivery* path for
the corruption, not command execution: no chosen pointer, ASLR-stable
target or benign side effect was observed, so the grade is unchanged and
r5 is not claimed. Evidence and hashes: `lab/frontier/rpm2shell/PROVENANCE.md`
and `lab/frontier/rpm2shell/real/wire/`.

### High-byte-preserving short writes (2026-11-26 23:3xZ)

`real/run-short-write.sh` tests the one remaining low-byte idea: the qword
at `buf+0` looks like a canonical heap pointer before the copy, so a 1-byte
write could change its low byte while unknown high bytes survive. The
helper `real/short-write/make-short.py` patches the cpio filesize from 64
to 1 and the first byte of the existing relocated fixture, refreshing the
six payload digests; the generator's default 64-byte output stays
byte-identical. Verified **30 PASS / 0 FAIL**. Twelve chosen low bytes
under ASLR-enabled GDB (observer only) gave, in 12/12 runs, preserved high
56 bits but `PRE_READABLE=0` — the qword is stale/unmapped, not a live
pointer — and no visited GCObject sharing its high 8, 16 or 32 bits
(`MASK8=0 MASK16=0 MASK32=0`, 310 visits per run). Three observed
`CHOSEN_VISIT=` lines matched the unchanged live qword at `buf+0x20`, not
the rewritten qword; all 12 plain ASLR installs exited rc 1 without a
fault. Controls: 64-byte vulnerable ASan `WRITE of size 64` (rc 134),
fixed ASan attack rc 1 clean, safe rc 0 clean, zero/short rc 1. This
CLOSES the short-write high-byte-preservation hypothesis in this layout;
no stable target, command or grade change follows.

## Duplicate check

`reports/frontier-*.md`, the wall's do-not-duplicate list and `lab/frontier/`
were checked before provisioning: no rpm brief, lab, window or admitted mind.
The Nov 2026 `libmt32emu` SysEx overflow (CVE-2026-121941) was screened out
because `munt2shell` is already admitted and its reports cover that library.
