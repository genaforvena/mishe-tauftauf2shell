# Frontier brief: rpm iterReadArchiveNext symlink-size wrap — CVE-2026-95520

Status: **STAGED 2026-11-26 by frontier W237**, awaiting operator admission;
witness replay UNKNOWN. Rung 3 pinned verbatim function; rung 4 PARTIAL
(chosen bytes observed past a one-byte allocation in a live plain process).
No real rpm build, no crafted RPM file, no wire input, no pointer, no command
and no rung 5.

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
  `rpm -qlvp` as reachable tools; none is exercised in these staged bytes.

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
- Vulnerable body (excerpt lines 60-62):
  `rpm_loff_t lsize = rpmfilesFSize(fi->files, fx);`
  `char *buf = (char *)xmalloc(lsize + 1);`
  `if (rpmcpioRead(fi->archive, buf, lsize) != lsize) rc = RPMERR_READ_FAILED;`
  `rpm_loff_t` is `int64_t`, so `UINT64_MAX` is `-1`, `-1 + 1 = 0`.
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
1-byte region comes from the stand-in `xmalloc(0)`. A plain build with 64
readable bytes behind the allocation prints
`CANARY_AFTER=495348452d52504d2121414141414141`: bytes 1..11 are the chosen
`ISHE-RPM!!` tail of `MISHE-RPM!!` (byte 0 lands inside the allocation) and
the rest are the chosen `A` filler. Fixed build on the same attack input is
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

## Grade and tractability

- **Rung 3:** GCC and Clang ASan-confirmed heap OOB WRITE in the verbatim
  pinned `iterReadArchiveNext()`, with fixed and safe-input controls.
- **Rung 4 PARTIAL:** the bytes are chosen in the harness and observed past
  the allocation in a live plain process; the offset is fixed by the
  allocation layout, and the copy length is capped by the stand-in. No real
  rpm build, crafted package, adjacent live object, pointer, wire or command.
- **Not rung 5:** no loopback target, no attacker-supplied package bytes
  through a real API, no pointer hijack, no command and no observed side
  effect.

Cheapest next experiment: build real rpm at the vulnerable parent with ASan
and use `rpm2cpio` on a synthesized package carrying a symlink header with
`RPMTAG_LONGFILESIZES = 0xFFFFFFFFFFFFFFFF` and a payload whose cpio entry
has a small controlled file size; measure the real `rpmcpioRead()` length and
whether the bytes land in a live adjacent object. Keep the no-pointer and
no-command ceiling until a real consumer and a fixed control are observed.

## Duplicate check

`reports/frontier-*.md`, the wall's do-not-duplicate list and `lab/frontier/`
were checked before provisioning: no rpm brief, lab, window or admitted mind.
The Nov 2026 `libmt32emu` SysEx overflow (CVE-2026-121941) was screened out
because `munt2shell` is already admitted and its reports cover that library.
