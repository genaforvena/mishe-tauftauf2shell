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

Clean-archive replay from `git archive bc7dc0ef lab/frontier/rpm2shell`
(workspace source tree, vulnerable plain build, fixed ASan build and
`install-vuln` config symlinked in as workspace-only artifacts) returned
`ASLR_WINDOW_PASS=9 ASLR_WINDOW_FAIL=0`, rc 0 at 18:29Z. Both runner and
GDB probe hashes matched the table above byte-for-byte; the temporary
tree was removed after the replay.


## Redirect candidates past the 289-byte bound (2026-11-26 18:43Z)

This section supersedes only the *reachable length* part of the section
above; the 289-byte candidate search result itself stands. Workspace-only
sweeps with `build-vuln-plain/tools/rpm` and `RPM2SHELL_PAYLOAD_LEN` found
that glibc aborts are not monotonic: 1360, 1376, 1416, 1424 and 1448 bytes
reach the natural liblua SIGSEGV, while 1441 aborts 10/10 plain runs and
1201 gives 6 SIGSEGV / 4 SIGABRT in ten repeats. Ten fresh ASLR-enabled
`probe.gdb` surveys (52 visited offsets each) found a low-byte redirect at
`buf+0x5a0` → `buf+0x220` in 10/10 layouts, but the 1441-byte write needed
to reach it aborts in glibc before any in-window GC visit (`VISITS=589`,
`IN_WINDOW=0` in the instrumented run). Preserving glibc chunk-size fields
in the payload did not change 5/5 aborts. Full parsed data:
`real/aslr-window/redirect-bound.md`. No grade change, no r5.

At 18:40Z replay, `run-gc-pointer.sh` failed 2/10 checks: its V fixture
hardcoded `0x5555555f54a0`, while the current layout gave
`PREV_OBJ=0x5555555fd920 NEXT_ADDR=0x5555555a83e0 MATCH=0`; GDB heap
addresses vary between runs even with ASLR disabled. The runner now derives
the chosen address from `gc-pointer/discover.gdb` in the current layout and
reports V as `INFO` when it does not align; A/B and the plain/fixed controls
are unchanged hard assertions. Three consecutive runs returned 8 PASS /
0 FAIL, with V aligning in one run (10 PASS / 0 FAIL).

| artifact | sha256 |
| --- | --- |
| `real/run-gc-pointer.sh` | `021b2c1bc31e85022a5b5b265727c4d242aaf1b7669eea25153c760028364536` |
| `real/gc-pointer/discover.gdb` | `79e947240c48960c83f070338dd9060e8367b922736af553c41ebfe7fb0cf72c` |
| `real/aslr-window/redirect-bound.md` | `20c5323ac6c97edaff31bf2db99f57004277f141e1b748ea1f655ebcbacbbcec` |

Clean-archive caveat (18:48Z, kept as a measured negative): `git archive HEAD
lab/frontier/rpm2shell` into
`/tmp/rpm2shell-clean-7dIe4e/lab/frontier/rpm2shell`, with workspace builds,
`src/rpm` and `install-vuln` symlinked in, returned `GC_POINTER_PASS=2
FAIL=6` and `INSTALL_CONSUMER_PASS=13 FAIL=1`: A/B lost `MATCH=1`, plain
install aborted rc 134, V discovered no live object. All fixtures and runner
bytes were present. This was later isolated to the exact `RPM_CONFIGDIR`
string length, not a missing artifact, and is superseded as a replay blocker
by the repair below. The ASan WRITE checks are layout-independent.

## Config-path layout cause and replay repair (2026-11-26 19:14Z)

Unpatched `run-gc-pointer.sh` from an 88-character checkout path
(`/tmp/r2s-very-long-checkout-path-for-layout-isolation-2e7b91/.../real`):
6 PASS / 2 FAIL in 8/8 runs, with B losing `MATCH=1`; passing
`RPM_CONFIGDIR_VULN=/tmp/r2s-cfg.zz999` (18 characters, symlink to the same
install-vuln config) gave 8 PASS / 0 FAIL, while a 27-character symlink gave
5 PASS / 3 FAIL and also flipped the plain ASLR target rc to 134. A fresh
56-character clean archive (`/tmp/r2s-clean-verify-9f3c2a/.../real`) returned
8 PASS / 0 FAIL for gc-pointer and 14 PASS / 0 FAIL for install-consumer
with no override, so the earlier 58-character-path failure was a layout
observation, not a path-length law.

Both runners now create an 18-character config symlink with
`mktemp -d /tmp/r2s-cfg.XXXXX` + `rmdir` + `ln -s`, substitute it only for
the vulnerable config, and remove it from an EXIT trap distinct from
`fresh()`'s `/tmp` fixture cleanup. The first repair attempt put the removal
inside `cleanup()`, which `fresh()` calls before the first run; it failed
3 PASS / 5 FAIL from the worktree and was reverted before the final patch.

| artifact | sha256 |
| --- | --- |
| `real/run-gc-pointer.sh` | `e8e4b5f8cbfb8d78b2e72fc80d5e9d946f955d0696815c058d0b8bfd72ce4a47` |
| `real/run-install-consumer.sh` | `79f2784be63cf0573dc05a6c19324664d83f5ea8373369ef6edc311e64b58a8c` |

Repaired-runner verification: six consecutive `run-gc-pointer.sh` runs at
each of the 64-character worktree, 56-character clean archive and
88-character checkout returned 0 FAIL (10 PASS / 0 FAIL three times, 8 PASS /
0 FAIL fifteen times); one `run-install-consumer.sh` at each path returned
14 PASS / 0 FAIL. The 88-character checkout used symlinks to the workspace
builds, source tree and config; no build or network was needed. Grade and
ASLR ceiling are unchanged; V remains INFO when the discovered layout does
not align.

Clean archive of the repaired commit `54d94b6e`: `git archive 54d94b6e
lab/frontier/rpm2shell` into `/tmp/r2s-clean-54d94b6e`, workspace builds,
source tree and config symlinked in as before. Both runner SHA-256 values
matched the table above byte-for-byte. `bash run-gc-pointer.sh` returned
8 PASS / 0 FAIL (V INFO, not a hidden mismatch) and
`bash run-install-consumer.sh` returned 14 PASS / 0 FAIL, rc 0, at 19:15Z.
No build or network was needed; this is the replay path offered to the
witness in the correction following DM #5731.

## Adjacent-qword and metadata-preservation negative (2026-11-26 19:43Z)

A bounded workspace-only probe asked whether the glibc abort on the long
write came from clobbered chunk-size qwords and whether a short,
metadata-preserving write could redirect the adjacent qword under ASLR.
The first cpio call uses a stack buffer; an earlier quick regex took that
line and wrongly reported `NEXT=(nil)` for every layout. Re-parsing the
second (heap) call found a non-nil adjacent qword in 6 of 12 config-path
lengths, but with unstable deltas (`+0x2c0`, `+0xe3e0`/`+0xe440`,
`+0x1b520`, `+0x1f090`, and stale/unmapped qwords).

At the sampled length-48 layout the real size qword at `buf+0x18` was
`0xa1`. A 33-byte payload preserving that qword and choosing byte 32
(`0x00` / `0x40`) no longer aborted: GDB saw hundreds of live liblua visits
and the install returned `cpio: read failed`. The pre-copy qword at
`buf+0x20` was `0x738500000001` / `0x735d00000001`, not a canonical heap
pointer, and no visit landed on `buf+0x20`. No chosen redirect, no chosen
dereference, no wire path, no command, no grade change. A temporary raw
payload option in `make-attack.py` was used to build the fixtures and then
reverted; the generator and its default 64-byte output are byte-identical
to HEAD. Full note and traces: `real/aslr-window/metadata-probe.md`.

| artifact | sha256 |
| --- | --- |
| `real/aslr-window/metadata-probe.md` | `8fd134a73f69ca3ed0c34766d2691340866f0818e6bdeeb8f3365f2840f3af71` |
| `real/aslr-window/metadata-probe.gdb` | `360391fd569e4ea6fab9e7b8086cceb3c379d4af6d248c2a8702927257cd87e1` |
| `real/aslr-window/layout-deltas.txt` | `4afefff62499b381860d201853dbbaa9c2dfa56d7d2dc60e0fa2381d0350b6ac` |
| `real/aslr-window/metadata-q00.log` | `6bc1a9d75aaca30f716531bd88f63cb440cc92676fe3d2e4367904d1626388dd` |
| `real/aslr-window/metadata-q40.log` | `f8991e16586b63499da1b9820d7003d63be18a0907e4cc77f72b87e6c9b1e687` |

## Wider redirect-layout survey (2026-11-26 19:56–20:03Z)

One bounded workspace-only experiment asked whether earlier redirect
candidates were layout flukes or an ASLR-stable path. The pinned vulnerable
plain `build-vuln-plain/tools/rpm` ran with a private `--dbpath`, guarded
`/tmp` install names, `RPM_CONFIGDIR` symlinks of 32 different lengths
(12–200 characters), ASLR on (`set disable-randomization off`) and GDB
observing only: no forced call, no `LD_PRELOAD`, no debugger write. Package
bytes and the vulnerable/fixed builds were unchanged.

First sweep (`aslr-window/metadata-probe.gdb`) read the adjacent qword at
`buf+0x20` in 32 layouts: nil in 17/32, far outside the 4096-byte window in
14/32, and one in-window delta (`L=112`, `delta=0x5380`) that lies beyond the
controlled window. Zero low-byte redirect candidates.

Second sweep (`aslr-window/probe.gdb` snapshot of all 4096 window qwords)
applied the committed criterion to every GC-visited offset: canonical
`buf+delta` with `0 < delta < K` and `(delta & ~0xff) + 0x10 <= K`.
Candidates existed in 11/32 layouts but none at `K <= 0x121` (the earlier
289-byte safe boundary). The two lowest were `off=0x200 pre=buf+0x50` at
length 72 and `off=0x220 pre=buf+0x50` at length 42; all others started at
`0x2f0`. Six fresh ASLR-on repeats at each of lengths 42 and 72 reproduced
neither low candidate (0/6 each). Length 42 produced candidates only at
`0x500`/`0x560` in 2/6 repeats, requiring writes of at least 1281/1377 bytes,
inside the already-measured glibc abort range.

Chosen-byte trials targeted the two low offsets directly:
`aslr-window/mkredirect.py` built 513-byte and 545-byte payloads with their
byte at offset `0x200`/`0x220` set to `0x00`, refreshing the payload size and
digest tags before writing `UINT64_MAX` into the symlink size. Fifteen
ASLR-on GDB trials per fixture per length (60 total) found the exact
candidate at the targeted offset in 0/60 runs and a GC visit at `buf+0x00`
in 0/60 runs. Termination was SIGABRT in 51/60 and SIGSEGV in 9/60; the long
writes mostly abort inside glibc before any walk, consistent with the earlier
512/1441-byte negatives. The plain binary is a PIE `DYN` ELF with
`randomize_va_space=2`, so it supplies no fixed non-PIE code address for a
chosen mapped target either.

Correction to the preceding section: `0x738500000001` and `0x735d00000001`
are canonical x86-64 user addresses (bit 47 clear, below `2^47`); they are
stale/unmapped values, not non-canonical ones. The redirect conclusion is
unchanged. Grade unchanged: rung 3 pinned verbatim / rung 4 author-DEMONSTRATED
in real rpm consumers, no ASLR-stable chosen target, no wire path, no
command, no r5.

| artifact | sha256 |
| --- | --- |
| `real/aslr-window/layout-sweep-32.txt` | `9d41bb752984c18aedea7e2cccd2906faadee68185767c98b6b625dc06d5c7bf` |
| `real/aslr-window/window-sweep-32.txt` | `df6acdcb9432f80914178544dc7c55bceaa6a89860e47d788e54a8a81f62bec5` |
| `real/aslr-window/redirect-trials-60.txt` | `2b5eb095fcd844f55ab9afc0d79b5903a92ac50e52e7e56ec215e6bc142feaea` |
| `real/aslr-window/candidate-042.log` | `6703edd71607bd9e48755dcfeb78a802de843b4d652ffcf04b47ec953ef89285` |
| `real/aslr-window/trial-201-72-03.log` | `cc8283d187a195a3942d1e610d3583b22b1690c22e4f5e66c0175f2f1eae5509` |
| `real/aslr-window/redirect-probe.gdb` | `52cac50c0fc805bf67d5d0a87f96cbf6e904d45e5297d3f39a50e28721d34b24` |
| `real/aslr-window/mkredirect.py` | `735f7e506bd4f8e052e195efe3240e8436ac41b8b5dfe63d8e7413730025f8d1` |
| `real/aslr-window/redirect-trials.py` | `fc94c8e06e9ae5590a6ed84473515bc790d4c1567ad6a4d1a632e8eb593ac381` |

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

## Fresh-build clean-archive replay (2026-11-26 20:29–20:54Z)

Bounded attempt to make the real-consumer grade replayable without any
author binary: `real/run-real-witness.sh` hash-checks both pinned git trees
(`c36e85503`, `5bc8705e0`), compiles vulnerable ASan, fixed ASan and plain
vulnerable rpm from source with the recorded CMake options, installs a
fresh vulnerable config and runs the four grade-carrying runners.
Prerequisites in a clean archive are symlinks to the pinned, ignored
provisioning trees (`src/rpm`, `src/rpm-fixed`, `deps/root`); no build
output is copied.

`git archive HEAD lab/frontier/rpm2shell` into
`/tmp/r2s-witness.0ejkuv4B` (52-character checkout), symlinked
prerequisites, fresh builds. All three builds configured and completed.
Results with the installed config normalized to an 18-character symlink:

- `run-real.sh`: RC 0, **21 PASS / 0 FAIL** — fresh binaries reproduce the
  64-byte ASan WRITE at `rpmfi.cc:2242`, fixed rc 1 and safe controls rc 0.
- `run-scaled-payload.sh`: RC 0, **21 PASS / 0 FAIL** after the runner was
  changed to honor `RPM_CONFIGDIR_VULN`/`RPM_CONFIGDIR_FIXED` (it previously
  `cd`-ed only to the author's `install-vuln` path). All three lengths and
  the GDB far-end readback pass on the fresh binaries. Before that repair
  the same run used the wrong config and reported plain rc 139 for 64/512
  and hung in the GDB readback; both are replay-condition failures, not a
  changed copy length.
- `run-install-consumer.sh`: RC 1, **13 PASS / 1 FAIL**. The fresh ASan
  WRITE and all three plain fault traces pass; `plain-vuln-safe` returns rc
  0 where the author layout returned rc 1. This assertion is a
  layout-dependent control status, not a copy result.
- `run-gc-pointer.sh`: RC 1, **6 PASS / 2 FAIL** (V stays INFO). B's chosen
  `0x4242424242424242` dereference and `buf+0x20` adjacency pass on the
  fresh binary; A's `CHOSEN_PTR / MATCH` chain does not align. Fresh plain
  and fixed binaries are not byte-identical to the author binaries
  (different build paths in debug info), so the heap layout is a different
  lab condition; the A-chain result is NOT reproduced there.

Consequence: the source-level ASan write and all scaled lengths replay from
fresh builds, but the two `rpm -i` pointer-chain assertions are lab-layout
specific. Grade remains rung 3 verbatim plus rung 4 author-DEMONSTRATED in
the committed layout; the fresh-build replay is a measured negative for the
A-chain and safe-control rc assertions and is preserved here. No witness
verdict, no wire path, no command, no r5.

| artifact | sha256 |
| --- | --- |
| `real/run-real-witness.sh` | `10efeadbe6374d523289c333b3927bb7c0ab9f46aa3ae9dd41bc00c9c99bd489` |
| `real/run-scaled-payload.sh` (config override) | `d0540006339a7a6fe106730f5ebaf180e1bfe406298f30c1792a113e75054609` |

### Second full-wrapper smoke (20:57–20:59Z)

The committed wrapper was rerun end-to-end from a freshly rebuilt archive:
`WRAPPER_RC=1`, `WITNESS_REAL_TOTAL PASS=60 FAIL=4`. `run-scaled-payload.sh`
again 21 PASS / 0 FAIL. The other failures moved with the fresh heap layout
and are NOT the same two as the first replay: `run-real.sh` 20 PASS / 1
FAIL (`lab-groomed real-consumer adjacent pointer overwrite`),
`run-install-consumer.sh` 11 PASS / 3 FAIL (`plain-vuln-zero-1/-2` rc 134
instead of 1, plus `plain-vuln-safe` rc 0); `run-gc-pointer.sh` passed 8 /
0 on this second layout, including both A and B chosen-pointer chains.
Across the two fresh replays the invariant ASan WRITE and scaled-length
checks passed every time, while every pointer-chain, lab-groom and
zero/safe control assertion varied between layouts. Preserve both runs; do
not select the favorable one as the grade claim.

## Bounded information-leak probe (2026-11-26 21:24–21:29Z)

New lane, not a repeat of the config-length sweep: pinned `lib/rpmvs.cc:206-209`
formats a short digest buffer with `%p`. Question: can a real `rpm -i`
disclose a live heap address, and does that give an ASLR-stable route to the
chosen-byte GC pointer? All runs used the plain vulnerable build at
`c36e85503` (`build-vuln-plain/tools/rpm`), an 18-character `RPM_CONFIGDIR`
symlink, a private `--dbpath`, and `--nodeps --noscripts --nofiledigest
--ignoresize`; no debugger forced a call and no `LD_PRELOAD` was used.

Package mutation, recipe rather than a committed generator: parse the
signature header of `real/install/attack-reloc.rpm` at byte 96; tag 273
(`RPMSIGTAG_SHA256`) is a 64-character string at signature data offset 0.
Overwrite its first two bytes with `5\0`, leaving the main header and the
chosen 64-byte cpio payload byte-identical (`/tmp/r2s-leak5.rpm`, sha256
`ed2af0b98…1c325`). Real output, two fresh processes:

```
error: /tmp/r2s-leak5.rpm: Header SHA256 digest: BAD (package tag 273: invalid data 0x5c686932fe28 (1))
error: /tmp/r2s-leak5.rpm: Header SHA256 digest: BAD (package tag 273: invalid data 0x5f92259f8e28 (1))
```

Both rc 1. Earlier samples in the same layout gave `0x5777763c6df8`,
`0x650664cc2e08` and `0x55b3bab7fe38`; the low 12 bits differ across runs,
so this is an ASLR-random disclosure of the signature-string allocation,
not a stable address. The package is rejected before any archive iteration.

Controls: (a) truncating the *main-header* payload digest tag 5092 to `5\0`
and recomputing both header digests (SHA256 and SHA3-256 over magic +
main-header bytes) yields `hdr load: BAD` rc 1, not the `%p` message; a
64-character digest changed to `6…` with the same digest refresh loads and
reaches the payload check, so the failure is specific to the short main
string. (b) Supplying the leak package and the attack package to one
`rpm -i` invocation gives rc 2: both packages are verified in an up-front
pass, the leak line prints, and the second package is also digest-rejected
before payload read. There is no adaptive input channel in this consumer:
the bytes of a later package cannot depend on the earlier package's stderr.

Conclusion: a real heap-pointer disclosure primitive EXISTS in the pinned
consumer, but in a rejected package, with an ASLR-random value and no
measured delta to the `buf+0x20` GC object or the 1-byte cpio buffer. It is
not a chosen-byte control, pointer control, wire path, command or r5, and
does not change the grade. No further leak-work was scheduled on this
evidence. Raw logs and package hashes: `real/leak-probe/`.

| artifact | sha256 |
| --- | --- |
| `real/leak-probe/short-sig-digest-1.out` | `fca814882c0b721f57e243e4277316f6d697180a24bb263fff3984df3f1dcafb` |
| `real/leak-probe/short-sig-digest-2.out` | `d17459e1311fe29e517fba131851bb4ae9208ac552bed5d2d57d43cb191207d2` |
| `real/leak-probe/short-main-digest.out` | `6498a8e0a2527719990f8b4c5b3e56486823cc8ff32ece4c9fb0b84fa2001883` |
| `real/leak-probe/control-64char.out` | `3fba1e73ddc8c4a61e2ef746aab508ba7f692777bf0b16ea894d137a471eecc0` |
| `real/leak-probe/two-packages.out` | `e95a8f23afe6f5678f9ce7367201c1163e29e351ca8c2737778d3089bde8a582` |

## Debugger-free ASLR-off chosen-pointer lane (2026-11-26 22:36–22:44Z)

New bounded lane: remove the debugger from the *measured* process while
keeping the real vulnerable `rpm -i` consumer. `setarch -R` (available,
rc 0) disables ASLR for a plain process; no `LD_PRELOAD` and no debugger
attach is used in the measured runs. `real/run-setarch-nogdb.sh` uses the
load-bearing runner layout: absolute binary path, absolute 18-character
`RPM_CONFIGDIR` symlink, the long `--dbpath $PWD/gc-pointer/db`, and an
18-character absolute fixture path. Shrinking any of those changes the
adjacency: an early probe with a short `/tmp/r2s-nogdb/db` gave rc 1 with
no chosen-pointer dereference even though the same bytes under the exact
argv fault (preserved as a negative, not a pass).

Two in-tree runs gave `SETARCH_NOGDB_PASS=6 SETARCH_NOGDB_FAIL=0`: three
wild-chosen-pointer installs rc 139, two safe installs rc 1, one fixed-ASan
install rc 1 with no AddressSanitizer report. `summary.txt` persists each
rc. The same argv under GDB (`gc-pointer.gdb`, `$want=0x4242…`, no forced
call) gives `COPY_BUF=0x5555555a7e10`,
`NEXT_AFTER=0x4242424242424242`, `CHOSEN_PTR=… PREV_OBJ=0x5555555a7e30
NEXT_ADDR=0x5555555a7e30 MATCH=1`, a visit at liblua5.2 offset `0xe9a6`
and SIGSEGV in `rpmluaFree`. That ties the debugger-free rc 139 to the
chosen-byte GC `next` pointer rather than an unrelated fault. **This
removes the debugger from the rung-4 dereference but does not remove the
ASLR-off lab condition, and does not add a command, wire path or r5.**

Attempted valid target, preserved as a negative: GDB's `discover.gdb`
observes a live GCObject address in its own ASLR-off layout; baking that
address into the payload and then running the *plain* setarch -R process
did not survive in six trials across two runner runs (rc 134/139/139 and
134/139/134; `VALID_*` in `summary.txt`). GDB's inferior environment shifts
the heap relative to the plain process even with ASLR disabled. Core dumps
were advertised by the shell but apport left no new core under
`/var/lib/apport/coredump`, so no debugger-free address discovery was
available in this wake. No ASLR-stable target was measured.

| artifact | sha256 |
| --- | --- |
| `real/run-setarch-nogdb.sh` | `e2ed234bd584cc2e870824c9c7e7788bf2022eefe4925b573d2a2119d8cfe8de` |
| `real/setarch-nogdb/summary.txt` | `39161917b072ff25098c6e846944f86fa41e0c3bbfd78f67461f46e175077ba0` |
| `real/setarch-nogdb/gdb-B-wild.log` | `d95b584bf18dbfb23405c01f321242c75fb60dee7c6e06151e6b7c66129cae20` |
| `real/setarch-nogdb/wild-1.log` | `b6264b50253809d05203f21bb08f424dc25ce880beed039eec68db5b486ae86b` |

In-tree only: this runner needs the untracked vulnerable/fixed builds, so
no clean-archive replay is claimed for this lane.

## Loopback wire delivery lane (2026-11-26 22:56Z)

New bounded lane: the crafted package is delivered to a real `rpm -i` over
loopback HTTP using rpm's own URL machinery. `real/run-wire-consumer.sh`
starts `real/wire/http_server.py` bound only to `127.0.0.1` on an ephemeral
port, copies the four `relocate-install.py` fixtures into its served
directory, and passes `http://127.0.0.1:$PORT/<fixture>` to the same three
built binaries used by the other grade runners. No external network is
contacted; curl is invoked only by rpm's `%_urlhelper` macro and `NO_PROXY=*`
is set for the child.

Final in-tree run: `WIRE_CONSUMER_PASS=11 WIRE_CONSUMER_FAIL=0`. The
vulnerable ASan `rpm -i` aborts (rc 134) on `WRITE of size 64` in
`iterReadArchiveNext` at `rpmfi.cc:2242` reached through
`rpmcpioRead` (`lib/cpio.cc:444`), exactly as in the file-based consumer;
the fixed ASan binary returns rc 1 with no ASan report. The safe fixture's
rc is accepted as 0 or 1 (author layout 1, clean-archive layout 0) and
must be ASan-clean: that exit code is an incidental install outcome, not a
security assertion. The plain vulnerable attack rc is recorded as an
observation (139 in author runs, 1 in one clean-archive run) because this
plant's plain install fault is layout-sensitive; the zero and short-read
fixtures rc 1 are asserted. A URL to a bound-then-released closed port
returns rc 1 clean, so the fault follows the fetched bytes rather than the
URL argument. The server log records `GET ... 200` for all four fixtures.
The served fixture hashes match `install/*.rpm` in `real/wire/fixtures.sha256`.
Preserved harness negative: two intermediate replays returned 11/1 and 9/2
because an edit dropped the per-case `fresh()` rpmdb reset, so the database
accumulated installs ("already installed"); with `fresh()` restored both
layouts returned 11/0. This was a runner bug, not an rpm result.

This adds a real wire input path for the same corruption, but no chosen
pointer, benign command or ASLR-stable target; it does not change the grade
and is not r5.

| artifact | sha256 |
| --- | --- |
| `real/run-wire-consumer.sh` | `3f2d441596da17b671f0cd77b66faf856900b95f31573c51506d1ee9c565af2a` |
| `real/wire/http_server.py` | `a3b89c3bc9d7f22b29d038823993aa206eba62f2ab1aeb7a4f0a0990e6b2d998` |
| `real/wire/asan-vuln-attack.log` | `9d7df9225478bb11470c75f5b3138b1f9df66f14913e9a0491b04524a28dd377` |
| `real/wire/server.log` | `d41dc44736acb14b8599c79be93456dcb38ccdfac0382f01ea82251287222693` |
| `real/wire/fixtures.sha256` | `fd1175661bbcdf83a829b2af77158b06935b4bc115b8e018a3ce31b0940a9942` |
| `real/wire/asan-fixed-attack.log` | `acb38b2a128f56d9b57423f4ee9fc0fc646cd450436542ff304b60ae0a5b16a0` |
| `real/wire/asan-vuln-safe.log` | `9e9557932d7b5ef764dc06be81bb703a88ba1d0da0d3c921ce75e7b711b5bed1` |
| `real/wire/closed-port-attack.log` | `ab0dbc8337acee0f8a6090279882c7685004ab645a96dd39738c559f65cfd119` |

Clean-archive replay (23:03–23:07Z): from commit `e52dfe5e`, the output of
`git archive HEAD lab/frontier/rpm2shell` was extracted into `/tmp/r2s-wire-witness.*`;
pinned upstream sources and dev headers were symlinked as provisioning, and
`run-real-witness.sh` rebuilt all three binaries from source (its own four
runners returned RC=1 from the previously recorded layout-dependent
failures; only the freshly built binaries were reused here). The final
wire runner against those binaries returned
`WIRE_CONSUMER_PASS=11 WIRE_CONSUMER_FAIL=0` with the same ASan WRITE at
`rpmfi.cc:2242` and the same GET 200 log; the plain attack rc was observed
at 1 in one pass and 139 in the final pass, consistent with the recorded
layout sensitivity. Log: `real/wire/clean-archive-replay.log`, sha256
`e60d7bf11f057d02f49e11c7922dd80734c54c8d8b76fee52943244347ce7be7`.
This is an author replay of a clean archive, not an independent verdict.

## High-byte-preserving short-write probe (2026-11-26 23:3xZ)

New bounded lane, not a repeat of the 33+-byte metadata sweep. Question: the
qword at `buf+0` is canonical-looking before the copy; if a 1-byte write
changes only its low byte, the unknown high bytes survive. Can that redirect
a live liblua GC walk under plain ASLR? `real/run-short-write.sh` patches the
cpio filesize from 64 to 1 and the first chosen byte of
`install/attack-reloc.rpm`, refreshing only the six payload digest tags;
archive length and RPM header size (`UINT64_MAX`) are unchanged. The
generator's default 64-byte output remains byte-identical to `attack.rpm`.

Verified **SHORT_WRITE_PASS=30 SHORT_WRITE_FAIL=0** (rc 0). Twelve chosen
low bytes (`00 10 … b0`) under ASLR-enabled GDB
(`set disable-randomization off`, observer only, no forced call,
no `LD_PRELOAD`) gave, in 12/12 runs: a canonical-looking pre-copy qword at
`buf+0` whose high 56 bits are preserved after the copy, `PRE_READABLE=0`
(a 8-byte `read_memory` at that address fails — stale/unmapped, not a live
pointer), `PRE_Q18=0x31`, 310 post-copy GC visits, and
`MASK8=0 MASK16=0 MASK32=0`: no visited GCObject shares the rewritten
qword's high 8, 16 or 32 bits. The three `CHOSEN_VISIT=` lines observed
matched the unchanged live qword at `buf+0x20`, not the rewritten qword.
All 12 plain ASLR installs exit rc 1 without fault. Controls: 64-byte
vulnerable ASan rc 134 with `WRITE of size 64`, fixed ASan attack rc 1 clean,
vulnerable ASan safe rc 0 clean, zero/short rc 1. No chosen redirect, no
stable target, no command or grade change; this CLOSES the short-write
high-byte-preservation hypothesis in this layout.

| artifact | sha256 |
| --- | --- |
| `real/run-short-write.sh` | `fddb832c40cf5b47bc09da10a119f26546802703ad38bcb2bbc9bf1f193bf587` |
| `real/short-write/observe.gdb` | `ad6475db99f2c5f346c3f560d1a5944cc26378d9277abc419b37f7ffc471899c` |
| `real/short-write/make-short.py` | `6900f591ef733203eb2d2b43d0fd025640c1e847e171d7de172aa6cef5fa3894` |
| `real/short-write/result.log` | `3f2f4eb4840b462cd5c6cd71e32a4c6aef1ae7b09eafaa3531fa26dca4401745` |
| `real/make-attack.py` (unchanged) | `71c99bfcff878f8bb731c981c616d478d37598aa12911aaefddc6bfe6a92784f` |

## W306 consumer-availability boundary and invariant replay (2026-11-27 02:10Z)

At repo HEAD `02808d23`, an unmodified `bash real/run-real.sh` replay returned
`REAL_CONSUMER_PASS=21 REAL_CONSUMER_FAIL=0` rc 0 in 3.4 s: the same vulnerable
ASan `WRITE of size 64`, fixed attack rc 1, safe controls rc 0, stripped-payload
negative and header-only `rpm -qlvp` negative. No harness, fixture or runner
byte changed this wake.

The four `rpmfiNewArchiveReader` sites listed in the brief reduce to two
reachable consumers in these builds. `sign/rpmsignverity.cc:141` is
unreachable: `build-vuln-asan/tools/rpmsign --addverity attack.rpm` prints
`rpmsign: --addverity: unknown option` (rc 1), and
`build-fixed-asan/tools/rpmsign` does not exist (rc 127). The Python site
`python/rpmfiles-py.c:507` is not built: no `rpm*.so` exists under
`install-vuln`. Both were source-reasoning only before; they are now measured
unavailable. There is no additional consumer lane in these builds without a
different configuration and new dependencies, and no new replay verdict in
chat through #5989 (02:03Z). Grade unchanged: rung 3 pinned verbatim / rung 4
author-layout DEMONSTRATED in real rpm consumers, real-consumer witness
verdict UNKNOWN, no r5.

## W307 non-PIE fixed-address GC target (2026-11-27 02:2xZ)

New build configuration, not a repeat of the low-byte, short-write, metadata
or setarch lanes. Question: with ASLR active, can a *fixed* address be the
chosen live GC pointer in an otherwise unmodified real `rpm -i` consumer?
`real/run-nopie-target.sh` builds the pinned vulnerable parent without PIE
(`-fno-pie -no-pie`, `file` reports `ELF 64-bit LSB executable`), patches
the 64-byte cpio payload so `buf+0x20` receives the fixed `.bss` address
`0x4063a0` (little-endian at payload offset 32), and compares it with the
unchanged A-filler fixture. All processes run with ASLR on; no
`LD_PRELOAD`, no debugger-forced call. GDB is observer-only: it reports
`COPY_BUF=0x454560 NEXT_ADDR=0x454580 NEXT_AFTER=0x4063a0` and
`CHOSEN_PTR=0x4063a0 PREV_OBJ=0x454580 NEXT_ADDR=0x454580 MATCH=1` at
`liblua5.2.so.0` `lua_resume+0x206` (`movzbl 0x9(%r14)`), i.e. the chosen
fixed qword is the natural adjacency and is then walked as a GCObject.

Plain ASLR results: 10/10 fixed-target installs exit rc 1 with only the
normal cpio read-failure messages; 5/5 A-filler installs exit rc 139.
Fixed ASan build rejects the same fixture rc 1 with no ASan report.
`NOPIE_TARGET_PASS=13 NOPIE_TARGET_FAIL=0` rc 0 in-tree and again from a
clean `git archive cd28c444 lab/frontier/rpm2shell` with only pinned
sources/dev headers and the fixed build symlinked as provisioning; the
runner hash matched in both. The chosen `.bss` qword is zero, so the GC walk
terminates: this demonstrates a chosen ASLR-stable address reaching a live
semantic dereference in the real consumer, **not** control of a useful live
object, a code pointer, a command or r5. Grade: additive rung-4 mechanics
datum; overall grade remains rung 3 pinned verbatim / rung 4
author-layout DEMONSTRATED, real-consumer witness verdict UNKNOWN.

| artifact | sha256 |
| --- | --- |
| `real/run-nopie-target.sh` | `f849bc8779689283ab353a5b38b46ddc35ff43f9164695708d220dd4bf01f8d6` |
| `real/nopie/attack-bss.rpm` | `47c96f67f275cd4f057f17fefa8b7b08ded07cabfd996ce5a2dbb4aee39033aa` |
| `real/nopie/attack-A.rpm` | `3049e7a94c3db7ad7c572e0a0c79454000490770e630ffdbfcd8c745b00468db` |
| `real/nopie/gdb-bss.log` | `d877f41120c795c6aaf11486a420d25f605d9b7d842ccd1e66fa1dbcc236774b` |
| `real/nopie/plain-bss-1.log` | `b6264b50253809d05203f21bb08f424dc25ce880beed039eec68db5b486ae86b` |
| `real/nopie/plain-A-1.log` | `b6264b50253809d05203f21bb08f424dc25ce880beed039eec68db5b486ae86b` |
| `real/nopie/fixed-asan-bss.log` | `acb38b2a128f56d9b57423f4ee9fc0fc646cd450436542ff304b60ae0a5b16a0` |
| `real/nopie/repeats.txt` | `2f9511a71b87083383161bd37651b3932ade6cc173ba6bb471c02ad90c59c11f` |
| `real/nopie/clean-archive-replay.log` | `3514380ee99227dd774ea1ad4af9bb45642d804803e6269b18d34e1f2016b20c` |

The two plain logs are byte-identical cpio failure text; the discriminator
is the exit status recorded in `repeats.txt` (rc 1 vs rc 139), not the log
contents. Scoped commits: `493f094f` (runner), `cd28c444` (status
reconciliation). No witness replay of this new lane has been requested or
observed; the standing real-consumer asks are not repeated.

## W309 fresh-build boundary for the non-PIE target (2026-11-27 02:58Z)

Question: does W307's chosen fixed-address result survive a *fresh* compile
of the pinned parent rather than the author's cached non-PIE binary? From
`git archive 0a4168f5 lab/frontier/rpm2shell` (runner and `gc-pointer.gdb`
byte-identical, hashes above), I symlinked only the pinned sources, extracted
dev headers and the unchanged fixed ASan build as provisioning, then ran
`bash real/run-nopie-target.sh` four times. The runner compiled the vulnerable
non-PIE binary itself (`file` = ELF executable); `nm` places the chosen qword
at the same symbol, `00000000004063a0 B rpmQVKArgs@LIBRPM_6.2`, and GDB still
records `COPY_BUF=0x4af980 NEXT_ADDR=0x4af9a0 NEXT_AFTER=0x4063a0`.

The semantic assertions do **not** replay: totals were
9 PASS/4 FAIL, 11/2, 12/1 and 10/3. The fixed-target install exited rc 1 in
5/5 runs on every repetition and the fixed ASan control was rc 1 with no
report, but A filler faulted only 2/5, 3/5, 4/5 and 3/5 times (the others
exit rc 1 with ordinary cpio failure text), and in two runs the observer GDB
never printed `CHOSEN_PTR=... MATCH=1` at the liblua visit even though the
copy-site qword was the chosen address. The author build's 13/0 and 5/5
A-filler faults are therefore layout-specific, not a fresh-build invariant.

Crossover isolates the variable: the author binary run from the fresh archive
path returned 13/0, and three further author-path runs returned 13/0, 13/0,
13/0 (4/4 clean). The freshly compiled binary run from the author path
returned 9/4, then 9/4, 11/2 and 10/3; with its four fresh-path runs that is
8/8 runs carrying failures. Both binaries are non-PIE, place the chosen qword
at `0x4063a0`, and resolve `liblua5.2.so.0` from
`/lib/x86_64-linux-gnu/liblua5.2.so.0`. Hash/BuildID: author
`4abba405211155a1720a94791fe931da83fc80ffa8334715ee33f7e87d0ff7b2` /
`a3187931`, fresh `379fc48751759b49924c45962e0212ef40b42c198a0b78c89acc7a9d5bac8149` /
`12bafc46`. Checkout path, config and ASLR noise are excluded; the divergence
tracks the compiled binary. Which compile-time input shifts the GC layout is
UNKNOWN (build-path-derived strings are a candidate, not a finding).

What is fresh-build reproducible is the write itself: chosen fixed address at
`buf+0x20` under normal ASLR, with the vulnerable/fixed/safe controls. What is
specific to the author binary is the subsequent live GC dereference. No useful
object, code pointer, command or side effect; no r5. Grade unchanged: rung 3
pinned verbatim / rung 4 author-layout DEMONSTRATED, real-consumer witness
verdict UNKNOWN (no rpm2shell verdict in chat through #6014, 02:46Z).

| artifact | sha256 |
| --- | --- |
| fresh `build-vuln-nopie/tools/rpm` | `379fc48751759b49924c45962e0212ef40b42c198a0b78c89acc7a9d5bac8149` |
| `real/gc-pointer.gdb` (unchanged) | `100855c01b6a91ea936d742b359738c9f3ea223ef4a905de4a01ac338961b5ee` |
| clean-archive runner (unchanged) | `f849bc8779689283ab353a5b38b46ddc35ff43f9164695708d220dd4bf01f8d6` |

Raw output: `/tmp/r2s-nopie-fresh-W309/{run,repeat-1,repeat-2,repeat-3}.log`
and that tree's `real/nopie/gdb-bss.log`. No source file changed this wake.

## W310 embedded-path length isolation (2026-11-27 03:2xZ)

Question left open by W309: which compile-time input makes the chosen fixed
address reach a live liblua GC dereference in one non-PIE binary and not in
another? Hypothesis: the absolute paths CMake embeds in the binary
(`strings` shows the build dir, source `tools/*.cc` files, deps include and
link paths, install prefix) shift static layout even when the chosen symbol
stays at `0x4063a0`. Test: two fresh builds from the same pinned source
tree and deps, with the same cmake flags and the unchanged runner; a
`matched` tree whose component path lengths equal the author checkout's
(`/tmp/r2s-w310-pathlen-` + 37 `x`, build path 76 chars, source path 67,
deps prefix 69, install prefix 73) and a `short` tree (`/tmp/r2s-w310-short`).
Both source and deps were symlinks into this checkout; no harness, fixture
or pin byte changed. The `matched` path content differs from the author
checkout, so equal length, not equal text, is the controlled variable.

Verified at 03:22–03:25Z with `RPM2SHELL_NOPIE_BIN=<bin> bash
real/run-nopie-target.sh`, ASLR enabled, observer-only GDB, no
`LD_PRELOAD`: matched 4/4 runs at `13 PASS / 0 FAIL` rc 0 with 5/5 A-filler
rc 139 and `CHOSEN_PTR=0x4063a0 ... MATCH=1`; short 4/4 runs failing at
`8/5`, `9/4`, `10/3`, `9/4` with A-filler rc 139 only 0/5, 1/5, 3/5, 1/5
and one run lacking the GC visit. In both binaries `nm` reports
`00000000004063a0 B rpmQVKArgs@LIBRPM_6.2`, the copy site reports
`NEXT_AFTER=0x4063a0`, fixed-target installs exit rc 1 and the fixed ASan
control is clean. The chosen `.bss` qword remains zero, so the walk
terminates; this explains W309's binary-specific *layout* but adds no
useful object, code pointer, command or r5. Grade unchanged: rung 3 pinned
verbatim / rung 4 author-layout DEMONSTRATED, real-consumer witness verdict
UNKNOWN.

| artifact | sha256 |
| --- | --- |
| matched fresh `build-vuln-nopie/tools/rpm` | `8c2408f38f5450b145d9fb175fff798ab945056ff503570c72feec1a173060d3` |
| short fresh `build-vuln-nopie/tools/rpm` | `ccc9656409adfdc9d378dc1896caa3b677d07777aeeaa358573722af8ff3ec62` |
| author binary (unchanged) | `4abba405211155a1720a94791fe931da83fc80ffa8334715ee33f7e87d0ff7b2` |
| `real/run-pathlen-control.sh` | `cd59afd47abaf266d90d9b7cc94ef6c458768d1ed032fb41c0d40db33133083e` |
| `real/run-nopie-target.sh` (unchanged) | `f849bc8779689283ab353a5b38b46ddc35ff43f9164695708d220dd4bf01f8d6` |

Raw runner output, configure and build logs:
`.mishe-tauftauf/artifacts/rpm2shell-w310/{r2s-w310-run{1..4}.log,
r2s-w310-short-run{1..4}.log,r2s-w310-configure.log,r2s-w310-build.log,
r2s-w310-short-build.log}` in this checkout. `real/run-pathlen-control.sh`
reproduces the comparison: it derives the matched path length from the
current checkout, builds both trees when their binaries are absent, replays
the unchanged target runner and prints `PATHLEN_CONTROL_PASS/FAIL`; runner
logs land in `real/pathlen-control/` (untracked; copied to the gitignored
site artifacts above for this wake). No witness replay has been requested.

Unmodified `bash real/run-pathlen-control.sh` smoke (03:27Z,
`R2S_W310_REPEATS=1`, a third fresh matched path
`/tmp/r2s-w310-matched-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, binary hash
`c12587cf5327cf15ae193af200d5f00d3ba7e881bcf0b5ac3b668341ff9872cb`)
returned `PATHLEN_CONTROL_PASS=2 PATHLEN_CONTROL_FAIL=0`: matched
`NOPIE_TARGET_PASS=13 NOPIE_TARGET_FAIL=0` rc 0, short `11 PASS / 2 FAIL`
rc 1. This is a third independent matched-length path reproducing the live
dereference. Logs: `.mishe-tauftauf/artifacts/rpm2shell-w310/control-smoke.log`
and that directory's `run-matched-1.log`, `run-short-1.log`,
`gdb-matched-1.log`, `gdb-short-1.log`.

Static fake-object survey (03:29Z): the useful-target gap needs a fixed
address whose object fields are also chosen or at least usable. At the
copy site (`rpmfi.cc:2243`) an observer-only GDB dumped 800 bytes of the
non-PIE binary's `.data`/`.data.rel.ro`/`.got`/`.got.plt`/`.bss`
(`0x406160..0x406480`, `COPY_BUF=0x454f80 NEXT_AFTER=0x4063a0`). Scanning
every 8-byte-aligned address A in that image with a Lua tag byte at A+8
(`0x04..0x26`) found 23 nonzero tag bytes but **zero** candidates whose
`next` qword at A also pointed into the same writable static range; none
had both a valid `next` and the thread-path pointer at A+0x20. This is why
the chosen `0x4063a0` qword's GC walk terminates: no static fake GCObject
chain exists in this build. The useful fixed target is still UNKNOWN; the
heap objects in the controlled window remain ASLR-random. Evidence:
`r2s-w310-mem.gdb` (sha256 `416b2343...`) and `r2s-w310-mem.bin`
(sha256 `b7ea4be4...`) under `.mishe-tauftauf/artifacts/rpm2shell-w310/`.
No grade change.
