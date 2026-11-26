# PROVENANCE — rpm2shell (frontier W237, 2026-11-26)

## Provisioning (read-only fetch, no external probing)

    mkdir -p lab/frontier/rpm2shell/src
    git clone --filter=blob:none --no-checkout \
        https://github.com/rpm-software-management/rpm.git lab/frontier/rpm2shell/src/rpm

Provisioned HEAD `7c4768a92e349c03d65eabc8ebde97faa83a756c`
(2026-11-25 09:34:46 +0100). Upstream fix found by `git log --all --grep`:
`5bc8705e0f9a9ffc123fb1c693bdad13de9f7c03` ("Sanity check symlink info while
iterating an archive (CVE-2026-95520)", author 2026-10-22, commit
2026-11-02); parent `c36e855034e604ef20863d541d44ef8c2dbac9e8`.
No tag contains the fix at this HEAD, so the pins are commit-level.

## Pins (SHA-256)

| artifact | sha256 |
| --- | --- |
| `pins/rpmfi-vulnerable.cc` | `51d5d7c96773ca2e00c20e5cba7f049d896300d9f255d0fffadd4193fa7ccf27` |
| `pins/rpmfi-fixed.cc` | `eaca65fdb04b9b8fe7647f2df4aa033d7b40d850500e7c82f9a91a3d87cb376a` |
| `pins/iter-vulnerable.inc` | `dd72be1bdb92c68b2d97e38f977344cc5b411c56ee16952e2d1010d8ed49e9ff` |
| `pins/iter-fixed.inc` | `0c00ded194575ec9649e3532ff09713faa5e96b36acb10524fb5adc776b92721` |

Byte-exact extraction from the cloned git objects (no reformatting):

    git -C src/rpm show c36e855034e604ef20863d541d44ef8c2dbac9e8:lib/rpmfi.cc > pins/rpmfi-vulnerable.cc
    git -C src/rpm show 5bc8705e0f9a9ffc123fb1c693bdad13de9f7c03:lib/rpmfi.cc > pins/rpmfi-fixed.cc
    sed -n '2182,2254p' pins/rpmfi-vulnerable.cc > pins/iter-vulnerable.inc
    sed -n '2182,2258p' pins/rpmfi-fixed.cc > pins/iter-fixed.inc

The excerpts contain `rpmfiSetFound`, `rpmfiFound` and the complete
`iterReadArchiveNext()` body. Fix hunk: `link == NULL || lsize != strlen(link)`
returns `RPMERR_BAD_HEADER` before the allocation.

## Harness facts

- `harness/driver.c` supplies stand-ins for `rpmfilesFC`,
  `rpmcpioHeaderRead`, `rpmfilesFindOFN`, `rpmfilesFFlags`,
  `rpmfilesFMode`, `rpmfilesFLinks`, `rpmfilesFSize`, `rpmfilesFLink`
  (fixed body only), `rpmcpioRead`, `rpmcpioSetExpectedFileSize`, the error
  constants, an `xmalloc` and a caller. Both bodies are `#include`d verbatim.
- Upstream `rpm_loff_t` is `uint64_t`; the advisory's `UINT64_MAX` makes
  `lsize + 1` wrap to zero exactly. The harness uses `int64_t` and represents
  the same bit pattern as `-1`; `-1 + 1` is also exactly zero. `xmalloc(0)`
  returns a 1-byte region under ASan.
- `rpmcpioRead()` stand-in copies `min(len, g_payload_len)` bytes; for the
  attack case that is 64 bytes from a chosen payload (`MISHE-RPM!!` then
  `0x41` filler) into the 1-byte region. The real function would copy the
  declared `lsize`; this cap is a harness limit, not a claim about rpm.
- Plain mode returns `malloc(sz + 64)` from `xmalloc`, suppresses `free` of
  the buffer via a macro, and reads 16 bytes at `buf + 1` after the call.
- GCC 13.3 at `-O1 -fsanitize=address` inlines `rpmcpioRead()` into the
  pinned function and does not report the overflow (`RET=-13`). All ASan
  binaries are therefore built at `-O0`; GCC and Clang both report the WRITE
  there. The `-O1` non-detection is preserved as a negative result.

## Real consumer lane (2026-11-26)

Reconciliation: the previous wake left the blobless clone with all 746 tracked
paths staged deleted; `git restore` timed out halfway. A full clone was made
at `c36e855034e604ef20863d541d44ef8c2dbac9e8`, with fixed worktree
`5bc8705e0f9a9ffc123fb1c693bdad13de9f7c03`. The incomplete clone is retained
as untracked `src/rpm-partial-restore-1795702560`.

Development files for popt 1.19, libarchive 3.7.2, libmagic and scdoc were
downloaded with `apt-get download` and extracted under `deps/root`; no host
package was installed. The popt/libarchive pkg-config prefixes were relocated
to that tree, and unversioned shared-library symlinks point at the host's
matching runtime libraries. Lua 5.2, zlib, bzip2, lzma, zstd and OpenSSL came
from the host.

Both real builds use GCC 13.3.0, Ninja, Debug/`-O0`, `ENABLE_ASAN=ON`,
`WITH_SEQUOIA=OFF`, `WITH_OPENSSL=ON`, Python/plugins/NLS/OpenMP and both
database backends off, and optional capability/ACL/audit/SELinux/DBus/
fapolicyd/libdw/libelf/readline integrations off. Workspace-only configure and
build logs are `configure-vuln.log`, `build-vuln.log`, `configure-fixed.log`
and `build-fixed.log`. A separate plain Debug vulnerable build is in
`build-vuln-plain` (`configure-vuln-plain.log`, `build-vuln-plain.log`).

`real/consumer.spec` is the upstream `tests/data/SPECS/filetypes.spec` recipe
with the symlink target changed to the equal-length `MISHE-RPM!!`. It was built
with `_binary_payload w.ufdio`, `_target_platform noarch-linux`,
`SOURCE_DATE_EPOCH=1234567890`, `optflags -O2 -g`,
`build_mtime_policy clamp_to_source_date_epoch`, weak user/group dependencies
off and autosigning disabled. The generated v6 package uses stripped cpio.

`real/make-attack.py` parses the RPM header and both cpio forms, verifies the
safe symlink's 11-byte size and payload, then emits the attack, safe-newc and
stripped-attack fixtures. It updates v6 payload-size and payload-hash tags when
replacing the payload; signature-header digests are intentionally stale, and
`rpm2archive`/`rpm2cpio` already disable digest/signature/header checks in
`tools/rpm2archive.cc:321-328`.

Replay:

    cd lab/frontier/rpm2shell
    bash real/run-real.sh

Author run 2026-11-26 15:15Z: **21 PASS / 0 FAIL**. Real vulnerable consumers
abort with ASan `WRITE of size 64` 0 bytes after a 1-byte region; fixed attack
returns 1 and all safe controls return 0. `real/adjacent.c` provides a
lab-only LD_PRELOAD `malloc(1)` seam which places a live marker-pointer guard
after the victim with tcache disabled; `plain-layout-groom.log` shows that
pointer overwritten by chosen `A` bytes. Natural unmodified layout varied:
`plain-layout.log` records one 0x31-chunk pointer hit, while
`plain-layout-sweep.log` records a later 12-miss sweep. Raw logs and rc files
are under `real/`.

## Natural adjacency dereference probe (2026-11-26 16:32Z)

    cd lab/frontier/rpm2shell
    bash real/run-natural-deref.sh

Verified `NATURAL_DEREF_PASS=52 NATURAL_DEREF_FAIL=0`,
`NATURAL_POINTER_ADJACENCY=4/20 READ_WATCHPOINT=20/20 INSPECT_POINTER=0/12`.
All 20 plain continuations past the copy exit 1 with no `SIGSEGV`; pinned
`rpmfi.cc:2242-2253` sets `RPMERR_READ_FAILED`, frees `buf` and returns, so
no later consumer uses the adjacent object. The read watchpoint fires even
when the adjacent qword was nil, at `rpmfi.cc:2245` one instruction before
`call free@plt`; that read is not value-dependent and is not a semantic
dereference. When pointer-bearing, the adjacent object is rpm header-import
data with tag word `0x00122204`, count 6 and inline `return`. Details and
sample logs: `real/natural-continue/README.md`.

## Scaled controlled copy length (2026-11-26 16:45Z)

    cd lab/frontier/rpm2shell
    bash real/run-scaled-payload.sh

Verified `SCALED_PAYLOAD_PASS=21 SCALED_PAYLOAD_FAIL=0`. `RPM2SHELL_PAYLOAD_LEN`
in `real/make-attack.py` sets the chosen symlink payload length (default 64);
the 64/512/4096-byte fixtures are `real/scaled/attack-{64,512,4096}.rpm`.
ASan vulnerable runs report `WRITE of size 64`, `512`, `4096` respectively,
0 bytes after the 1-byte region at `rpmfi.cc:2242`, rc 134. Fixed ASan
`attack-4096.rpm` returns rc 1 ASan-clean; safe newc returns rc 0 ASan-clean.
Plain vulnerable `rpm2cpio` returns rc 1 with no fault at all three lengths.
`real/scaled/gdb-readback-4096.log` prints `SCALED_BUF=... LSIZE=-1`,
`MISHE-RPM!!` at `buf`, and `0x4141414141414141` at `buf+4088`.
`build-vuln-asan/tools/rpm2cpio` and `build-vuln-plain/tools/rpm2cpio` are
symlinks to `rpm2archive` in these builds; the two CLI names are not
independent consumers. A wrong-relative-`RPM_CONFIGDIR` GDB run faulted in
`tvsub`; the absolute-config rerun (`real/scaled/gdb-bt-4096.log`) exited 1
with no stack, so the earlier fault is not claimed.

| artifact | sha256 |
| --- | --- |
| `real/run-scaled-payload.sh` | `046cfc490a19e054a8bcb65f6f05e7b21bf89f321841f162ef24c7eeab8e80bb` |
| `real/make-attack.py` | `71c99bfcff878f8bb731c981c616d478d37598aa12911aaefddc6bfe6a92784f` |
| `real/scaled/readback-4096.gdb` | `8a28d0557fab7ca2fdfba439f26d8b63ecef3299024297ff4fe997472a214b07` |
| `real/scaled/asan-rpm2cpio-4096.log` | `bd2c06db0ae738ab2766f6f4ef6419901a4bf808883d5ab7bd6269329c3ade35` |
| `real/scaled/gdb-readback-4096.log` | `6a276e3ba49bbeb8ee1f1b4469b0b96ec9a9a8b0a4140766746f5b36047ddeee` |

| artifact | sha256 |
| --- | --- |
| `real/run-natural-deref.sh` | `a11612b9b7c08d710ab58d4033561230576df6e95a7f11ac7bfbeaf16bc192df` |
| `real/layout-continue.gdb` | `55469d033eda7660112075f78fc6aea760b2ad2515bf9917bb1feb36ff3f3bd3` |
| `real/rwatch-after.gdb` | `8af2955cae1f4f9521aaa9ce35996b855959416a32ed252ff258eddbec89eea0` |
| `real/inspect-adjacent.gdb` | `91f749037e99aa6819e9889f6e3e543d1e8ff1067c29657fe24d6715df0455f3` |

## Verification

    cd lab/frontier/rpm2shell
    bash run-all.sh

Author run 2026-11-26 01:52Z: **28 PASS / 0 FAIL**, rc 0. Raw logs in
`out/gcc-attack.log`, `out/clang-attack.log`, `out/fixed-attack.log`,
`out/vuln-safe.log`, `out/fixed-safe.log`, `out/plain-attack.log`,
`out/plain-safe.log`, `out/plain-fixed-attack.log`.
`bash run-witness.sh` rehashes the four pins, rebuilds every binary and
asserts the same evidence; clean-archive replay is recorded in
`reports/rpm2shell-status.md`.
