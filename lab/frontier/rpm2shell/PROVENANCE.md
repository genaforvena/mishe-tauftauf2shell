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
- `rpm_loff_t` is `int64_t`; the advisory's `UINT64_MAX` is represented as
  `-1`, so `lsize + 1` is exactly zero without signed overflow. `xmalloc(0)`
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
