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

## Independent install (`fsm`) consumer probe (2026-11-26 17:00Z)

    cd lab/frontier/rpm2shell
    bash real/run-install-consumer.sh

Verified **INSTALL_CONSUMER_PASS=14 INSTALL_CONSUMER_FAIL=0**. The runner
regenerates `attack.rpm`/`safe-newc.rpm` with the unchanged
`real/make-attack.py` CLI, then `real/relocate-install.py` writes four
equal-length path-relocated fixtures under `real/install/`. Each install
uses a private `--dbpath`, `--nodeps --noscripts --nodigest --nosignature
--nofiledigest --ignoresize`; the four `/tmp` package names are guarded and
cleaned by a trap. Vulnerable ASan `rpm -i` rc 134 with
`AddressSanitizer: heap-buffer-overflow`, `WRITE of size 64`, write frame
`iterReadArchiveNext rpmfi.cc:2242` via `rpmfiNext :867`; fixed ASan rc 1
ASan-clean. Vulnerable plain `rpm -i` rc 139 in 3/3 runner runs (5/5 in an
earlier manual repeat); `attack-zero-reloc.rpm` and `short-read-reloc.rpm`
rc 1 in 2/2 runner runs each (3/3 each manually), safe-newc rc 1 without a
fault. `real/install/gdb-plain-attack.log` records the natural `SIGSEGV` in
`liblua5.2.so.0` via `rpmluaFree` ← `rpmFreeRpmrc` ← `rpmcliFini` ← `main`.
Manual B-filler repeats were 3/3 rc 139. No `LD_PRELOAD` or debugger-forced
execution was used in any rc observation; the GDB run only records the
backtrace. The corrupted object's identity stays UNKNOWN.

| artifact | sha256 |
| --- | --- |
| `real/run-install-consumer.sh` | `da1de8f74b914ba6c9ad450782568247ea8c464f919c8cafa1f9a2009488eae8` |
| `real/relocate-install.py` | `25ac3fbda8d5496968e9ae942ccff9ed97f39bd403d5685660cfba60fd4a2baa` |
| `real/install/attack-reloc.rpm` | `3049e7a94c3db7ad7c572e0a0c79454000490770e630ffdbfcd8c745b00468db` |
| `real/install/attack-zero-reloc.rpm` | `ab97e02fecdf432b120a7f62e95990dcc3394a37e1b836774d357c251c127a41` |
| `real/install/short-read-reloc.rpm` | `831534eeee6d409b674c972f09d5eba9dee7d5400f68919cc8a55d93203496df` |
| `real/install/asan-vuln-attack.log` | `390d4b7f1af8a50943fdb22c7af20016620de55ecc212194ba6daa993d29b504` |
| `real/install/gdb-plain-attack.log` | `95f30085da1c0701b1984c6844b4e6122c4b3ed5c65539e42f4b100fb0cb9289` |

## Chosen-byte GC pointer dereference (2026-11-26 17:30Z)

    cd lab/frontier/rpm2shell
    bash real/run-gc-pointer.sh

Verified **GC_POINTER_PASS=10 GC_POINTER_FAIL=0**. The runner uses the plain
vulnerable Debug `rpm -i` with a private `--dbpath`, no `LD_PRELOAD` and no
debugger-forced call; the four `/tmp` package names are guarded and cleaned.
`real/gc-pointer.gdb` sets a pending breakpoint at pinned `rpmfi.cc:2243`
and a Python breakpoint at `liblua5.2.so.0` offset `0xe9a6`
(`lua_resume+0x206`, `movzbl 0x9(%r14),%r13d`), gated on the copy so an
incidental startup visit cannot match. A filler sample:
`COPY_BUF=0x5555555a8600 NEXT_ADDR=0x5555555a8620
NEXT_AFTER=0x4141414141414141` and `CHOSEN_PTR=0x4141414141414141
PREV_OBJ=0x5555555a8620 NEXT_ADDR=0x5555555a8620 MATCH=1`; `%r14`/`%rdx`
hold the chosen value and `stepi` faults in the liblua GC walk under
`rpmluaFree`. B filler reproduces the chain with `0x4242424242424242`.
`attack-validtarget.rpm` writes the little-endian live GCObject address
`0x5555555f54a0` into the same payload qword; `V.log` records `MATCH=1`
and a non-faulting dereference under GDB's ASLR-disabled layout, while the
plain ASLR run of the same bytes faults rc 139. Zero-filler and short-read
controls return rc 1 without a fault; fixed ASan attack rc 1 ASan-clean.

| artifact | sha256 |
| --- | --- |
| `real/gc-pointer.gdb` | `100855c01b6a91ea936d742b359738c9f3ea223ef4a905de4a01ac338961b5ee` |
| `real/run-gc-pointer.sh` | `6d9ae836287adacc21f4ed3a64e59a89c4cb766cd09b8d04cb23c02cd4530a8c` |
| `real/gc-pointer/A.log` | `2b25230bb758322d66667dc1eae2d2abcc9cedad117e4fda6b1f9716a0cf6fa4` |
| `real/gc-pointer/B.log` | `94ae87715802c13ef284e11e080f2515269e5a9d2d163743acc5706fd4790abb` |
| `real/gc-pointer/V.log` | `3a190b3da653b829fe8ae76016867c63a7f1516eb30eb129f229d756639ee07f` |
| `real/gc-pointer/attack-validtarget.rpm` | `df41e11e5d0cb4258eb6ecba5805f073d18a19299d1e21cd6256719d79a5fbc3` |
| `real/gc-pointer/plain-validtarget.log` | `b6264b50253809d05203f21bb08f424dc25ce880beed039eec68db5b486ae86b` |

## Measured ASLR ceiling (2026-11-26 18:04Z)
    cd lab/frontier/rpm2shell
    bash real/run-aslr-ceiling.sh

Clean-archive replay from `git archive c2cc89b3 lab/frontier/rpm2shell` with
the prebuilt vulnerable/fixed trees and the install fixture symlinked in
(both are workspace-only artifacts) also returned 8 PASS / 0 FAIL at
18:07Z; the temporary tree was removed afterwards.

Verified **ASLR_CEILING_PASS=8 ASLR_CEILING_FAIL=0**, rc 0. The runner keeps
the same private `--dbpath` and guarded `/tmp` names as the install runner.
`real/aslr-ceiling/pre-copy.gdb` enables ASLR (`set disable-randomization
off`) and only observes: at `rpmcpioRead()` entry the qword at `buf+0x20`
is `0x7ffc7362ac70` stack-entry sample and `NEXT=(nil)` for the 1-byte
heap buffer; at pinned `rpmfi.cc:2243` the same qword is
`0x4141414141414141`. No high heap bytes exist to preserve with a short
write. Fixture `attack-vsyscall.rpm` writes the fixed address
`0xffffffffff600000` into that qword; three plain ASLR `rpm -i` runs
faulted rc 139 (`/proc/self/maps` shows the page as `--xp` on kernel
6.8.0-149-generic, so the read itself faults). Fixture
`attack-len33-reloc.rpm` uses `RPM2SHELL_PAYLOAD_LEN=33` to write only the
low byte; three plain runs aborted rc 134 with `double free or corruption
(out)` before any GC walk; fixed ASan rc 1 ASan-clean. Earlier exploratory
64-byte runs showed ASLR-random heap bases (e.g. `0x60d336d81600`) and a
nil original qword in 3/3; those throwaway logs were removed after this
runner captured the same result.

| artifact | sha256 |
| --- | --- |
| `real/run-aslr-ceiling.sh` | `8ac6fa5ef4a15239a9415a6e502bb1874463b9d1d5fa57475e2027e4c6188e09` |
| `real/aslr-ceiling/pre-copy.gdb` | `c8f7b741196b0bd574a8163fb3ccdf25014c12cb9b2fe02abfeda5a6f3e8df15` |
| `real/aslr-ceiling/pre-copy.log` | `542ef24d415bcbd8688fed8fda6fa2a637cc4c259121e57d597746199e6a3488` |
| `real/aslr-ceiling/vsyscall-1.log` | `b6264b50253809d05203f21bb08f424dc25ce880beed039eec68db5b486ae86b` |
| `real/aslr-ceiling/len33-1.log` | `1b413635732151aa41408fbee343b06720151cfb2d41b2698fc0386f07a54c93` |
| `real/aslr-ceiling/fixed-len33.log` | `acb38b2a128f56d9b57423f4ee9fc0fc646cd450436542ff304b60ae0a5b16a0` |


## Live GC objects in the copy window (2026-11-26 18:24Z)

`bash lab/frontier/rpm2shell/real/run-aslr-window.sh` returned
**ASLR_WINDOW_PASS=9 ASLR_WINDOW_FAIL=0**, rc 0. The runner rebuilds no
trees: it uses the same workspace prebuilt `build-vuln-plain/tools/rpm`
and `build-fixed-asan/tools/rpm` as the ceiling runner, guarded `/tmp`
names and a private `--dbpath`. Three ASLR-enabled GDB observations of
the plain `rpm -i` install of `install/attack-reloc.rpm` snapshot the
4096-byte window at `rpmcpioRead()` entry and log every visit at
`lua_resume+0x206`. Each run reported `WINDOW_VISIT_OFFSETS=78` and
`WINDOW_REPORT_DONE=1`; the qword at `buf+0x20` is chosen `A` filler after
the copy and the walk ends in liblua with SIGSEGV. Disassembly of the
host `liblua5.2.so.0` at the breakpoint confirms the GC-list step
`mov (%r14),%r14; test %r14,%r14; ... movzbl 0x9(%r14),%r13d` at
offset `0xe9a6` (`lua_resume+0x206`).

Across the three runner layouts plus ten earlier sampled layouts (all
ASLR on, same 64-byte fixture), zero visited offsets `K <= 0x121` held a
canonical pre-copy pointer `buf + delta` with `0 < delta < K` and
`(delta & ~0xff) + 0x10 <= K`, the shape a one-byte redirect onto
controlled bytes needs. Most low-offset qwords were nil or pointed well
outside the window; canonical pointers that do point back into the
window start at offset `0x170` or higher and require writes of 1185
bytes or more. Plain-install boundary probes: `RPM2SHELL_PAYLOAD_LEN=289`
faulted 2/2 rc 139 in liblua; `1377` aborted 2/2 rc 134 with
`double free or corruption (out)` before any GC walk; fixed ASan rc 1,
no ASan report. No chosen ASLR-stable target, wire path, command or r5.

| artifact | sha256 |
| --- | --- |
| `real/run-aslr-window.sh` | `8a5e89cc9928d0f53aa4eaa0439231b01acc3130dc714e58818f4ec37693b61a` |
| `real/aslr-window/probe.gdb` | `cfda607f2bb4426935128876c99ca8dd01558b729275751f9112281f2f354083` |
| `real/aslr-window/probe-1.log` | `16a02e6b1b67cc585915133d310e71fd210c5302a525832040eb79dd20ec3cac` |
| `real/aslr-window/len289-1.log` | `b6264b50253809d05203f21bb08f424dc25ce880beed039eec68db5b486ae86b` |
| `real/aslr-window/len1377-1.log` | `fe9f5b64e067733d78afc0ae4fee9840397006a25ca33c3fdb53769f2be7b1b4` |
| `real/aslr-window/fixed-len1377.log` | `acb38b2a128f56d9b57423f4ee9fc0fc646cd450436542ff304b60ae0a5b16a0` |

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
