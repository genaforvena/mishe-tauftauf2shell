# Frontier brief: rpm iterReadArchiveNext symlink-size wrap — CVE-2026-95520

Status: **real-consumer lane measured 2026-11-26**. Rung 3 is confirmed in
the pinned function and real rpm; rung 4 is DEMONSTRATED by a crafted RPM
writing 64 chosen bytes past a 1-byte allocation in real `rpm2cpio` and
`rpm2archive`, including a pointer-bearing lab-groomed adjacent allocation
in the plain consumer. Independent witness replay of this new lane
is pending. No pointer hijack, wire target, command or rung 5.

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
with `RET=-13` and no report. At W238 time there was no real rpm build,
crafted package, wire input, pointer, command or r5; the real-consumer lane
above is later work and still lacks an independent witness. Full W238 detail:
`.mishe-tauftauf/artifacts/witness-w238-rpm2shell/detail.md`.

## Grade and tractability

- **Rung 3:** GCC and Clang ASan-confirmed heap OOB WRITE in the verbatim
  pinned function, plus real rpm `rpm2cpio` and `rpm2archive` WRITE reports
  with fixed and safe-input controls.
- **Rung 4 DEMONSTRATED:** 64 chosen bytes past a real 1-byte allocation;
  plain GDB observes the bytes and a lab-groomed live pointer-bearing
  allocation overwritten by chosen `A` bytes. Natural adjacent layout varies,
  and pointer target control/downstream use remain UNKNOWN.
- **Not rung 5:** no loopback service or wire request, no controlled pointer
  hijack, no command and no observed command side effect.

Next experiment: identify a naturally adjacent object and test whether a
non-crashing chosen pointer value reaches a downstream dereference in the
real consumer. Keep the allocator instrumentation and stripped/query
negatives attached to any broader claim. No command execution without a live
target and benign side effect.

## Duplicate check

`reports/frontier-*.md`, the wall's do-not-duplicate list and `lab/frontier/`
were checked before provisioning: no rpm brief, lab, window or admitted mind.
The Nov 2026 `libmt32emu` SysEx overflow (CVE-2026-121941) was screened out
because `munt2shell` is already admitted and its reports cover that library.
