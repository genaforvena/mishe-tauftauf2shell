# Frontier brief: FCEUX UNIF MAPR board-name heap write — CVE-2026-136918

Status: **STAGED 2026-11-25 by frontier W233**, awaiting operator admission
and witness replay. Rung 3 pinned verbatim function; rung 4 PARTIAL
(file-chosen bytes at chosen offsets past a 1-byte heap allocation). No
adjacent-object target, pointer control, network consumer, command execution
or rung 5. Witness UNKNOWN.

## Claim and scope

- CVE-2026-136918, published on the NVD feed 2026-11-25 (CNA VulnCheck);
  NVD record: <https://nvd.nist.gov/vuln/detail/CVE-2026-136918>.
  The GHSA ids named in upstream issue #862 could not be resolved (HTTP 404)
  and are **not** claimed to be this CVE.
- Project: TASEmulators/fceux, `src/unif.cpp`, static `SetBoardName()`,
  reached from `LoadUNIFChunks()` on a `MAPR` chunk in a crafted `.unf` ROM.
- Affected: all releases before **2.8.0** (semver `< 2.8.0` per NVD); fixed in
  **2.8.0**, tag commit `c40fcf6319cf5e03cf39e4295e553045e695c22c`.
- Advisory CWE is **CWE-190** (integer wraparound) with a claimed heap
  out-of-bounds write; the write is confirmed locally, the wraparound is the
  claimed cause. CVSS v4 8.5 `AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`.
  This is a local, user-interaction file load — not a demonstrated remote path.

## Pins and source-bound mechanism

- Vulnerable pin: parent of the fix, `1e1de9b70a4c62d30f197b5741b64968094bd2cf`,
  `pins/unif-parent.cpp`; fixed pin: fix commit
  `d9132c2a37bf05e31b8a09f9ad938d46ff193bf1`, `pins/unif-fixed.cpp`.
- Upstream patch `pins/unif-fix.patch` (+26/-4, only `src/unif.cpp`):
  <https://github.com/TASEmulators/fceux/commit/d9132c2a37bf05e31b8a09f9ad938d46ff193bf1>.
- Vulnerable `SetBoardName()` (`unif-parent.cpp:280-290`):
  `FCEU_malloc(uchead.info + 1)` with `uint32 info`; a declared size of
  `0xffffffff` wraps the allocation argument to 0. The subsequent
  `FCEU_fread(boardname, 1, uchead.info, fp)` copies the file's remaining
  bytes into that allocation, and `boardname[uchead.info] = 0` stores far
  outside it.
- The fix converts to `size_t info`, checks the short read
  (`FCEU_fread(...) != info` returns 0), guards `info >= 4` before the
  `memcmp` prefix checks, and adds a declared-size-vs-remaining-file check
  in `LoadUNIFChunks()`. The `maxSize = size_t max - 1` guard is inert for a
  `uint32` length on LP64; the read check and file-size check are load-bearing.
- Harness `lab/frontier/fceux2shell/harness/driver.cpp` copies both
  `SetBoardName()` bodies and the chunk-header parse verbatim from those
  pins; only the `FCEUFILE` wrappers are stand-ins (real `FILE*`, `fread` and
  `malloc`). No emulator source tree is built.

## Local evidence

The 27-byte attack file is `MAPR` + little-endian `ffffffff` + payload
`TAU,ffMISHE-FCEUX!!`. The 16-byte control is `MAPR` + `08000000` +
`NES-TEST`. `bash lab/frontier/fceux2shell/run-all.sh` on the staged builds:
**14 PASS / 0 FAIL**.

GCC ASan on the vulnerable binary:

```text
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 19
#0 fread ... #1 FCEU_fread driver.cpp:32 #2 SetBoardName driver.cpp:55
0 bytes after 1-byte region [0x502000000010,0x502000000011)
allocated by malloc
```

Clang ASan reports the same write. Both fixed binaries reject the truncated
chunk before `SetBoardName()` and are clean; both vulnerable binaries accept
the safe chunk and print `OK board=TEST`.

In the vulnerable plain build, the short read places file-selected bytes
past the allocation; the later wild terminator store faults, and a
signal-safe handler reads the bytes from the still-live pointer before
exiting (rc 42):

```text
PAST_ALLOC=41552c66664d495348452d4643455558
```

That is payload bytes 1..16 (hex of `AU,ffMISHE-FCEUX`) landing at
`boardname+1` .. `boardname+16` immediately past the 1-byte region. The
fixed plain build yields rc 0 and no marker; three independent replay
classes (GCC ASan, Clang ASan, plain) agree.

## Grade and tractability

- **Rung 3:** GCC and Clang ASan-confirmed heap OOB WRITE in the verbatim
  pinned `SetBoardName()` path, with fixed and safe-input controls.
- **Rung 4 PARTIAL:** file-chosen bytes at chosen offsets immediately past
  the allocation, observed in a live plain process. The observation is via
  a SIGSEGV handler on the wild terminator store, not via a subsequent
  controlled consumer; no adjacent object is targeted.
- **Not rung 5:** AV:L/UI:P; no socket, live emulator process, pointer
  hijack, benign command or observed side effect.

Cheapest next experiment: build the pinned FCEUX 2.7.x ROM loader with a
real `.unf` load path and inspect the heap neighborhood of the zero-sized
`boardname` allocation; test whether a chosen chunk can place the payload
over a pointer-bearing object. Separately, find a real consumer that
auto-loads untrusted ROM files to test whether the AV:L caveat can be
replaced with a wire boundary.

## Alternatives screened this wake

- nfdump `nfcapd` (GHSA-gpgq-hv9x-7mqj, published 2026-11-25, network-facing
  EXgenericFlow OOB write, fix `32b9cbe7`, parent `8a00543a`, no tagged fixed
  release) was found by the second scout and is duplicate-clean. It is
  proposed as the **next** candidate: no local build or harness was started
  for it this wake, so no rung is claimed here.
- FCEUX was checked against `reports/frontier-*.md` and the wall's
  do-not-duplicate list before provisioning; no prior FCEUX lane exists.
