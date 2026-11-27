# Frontier brief: libssh-sftp-longname2shell — SFTP server long-name stack overflow

**Status: FRONTIER-STAGED 2026-11-27 W338; operator admission and independent
witness replay UNKNOWN.** Claim: CVE-2026-15370 / GHSA-6j7f-8jjp-mm8c
(CWE-121), unsafe SFTP server long-name construction. Lab:
`lab/frontier/libssh-sftp-longname2shell/`; source/patch pins and reproduction
commands are in that tree. Live inner-socket window 219 (`%444`/`%445`,
`dead=0`), registry 220/220 unique names. No libssh server, SFTP client,
listener or remote wire input was run.

## Verified ground truth

- Primary source: `https://www.libssh.org/security/advisories/CVE-2026-15370.txt`
  (published 2026-07-21); GitHub mirror `GHSA-6j7f-8jjp-mm8c` is unreviewed.
  Upstream libssh `>= 0.11.0` and `< 0.11.5`, plus
  `0.12.x < 0.12.1`, are affected; `0.11.5` and `0.12.1` are fixed releases.
  CVSSv3.1 is 6.7 `AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H`.
- Fix: `b2065f71c905d347b5e8dd7f8e24856807d71e99`; exact parent
  `8b2809ae13e1030a06e8699a248520934c08ba81`. Both complete
  `src/sftpserver.c` files and the full fix patch are SHA-256 pinned.
- The prerequisite is **not** a remote client choosing a filename. A local
  attacker controls a directory entry on a filesystem that permits long
  filenames; a user then causes the SFTP server to list that directory. The
  overflowing bytes must be valid filename bytes.
- Grade: R1/R2/R3 ✓; R4 LIMITED (chosen bytes at chosen stack offsets in the
  direct-call harness); R5 NOT CLAIMED (no live process, saved IP/pointer,
  marker or command side effect).

## Source-bound mechanism

`MAX_LONG_NAME_LEN` is 350 (`src/sftpserver.c:62`). `process_readdir()` declares
`char long_name[MAX_LONG_NAME_LEN]` (`:1904`) and calls
`readdir_long_name(dentry->d_name, &st, long_name)` (`:1920`). The sink builds a
permission/stat prefix in `long_name`, formats the timestamp and filename into
`tmpbuf[350]` (`:1851`), then appends it with unbounded
`strcat(z_long_name, tmpbuf)` (`:1852`). The fix uses
`strlcat(z_long_name, tmpbuf, MAX_LONG_NAME_LEN)`.

The source-bound server path is authenticated SFTP `READDIR` →
`process_readdir()` → `readdir()` → `readdir_long_name()`. The filename comes
from the filesystem, not the SFTP request. This path was read from pinned
source and was not executed.

## Cheapest local experiment and result

`gen_driver.py` copies the complete pinned `readdir_long_name()` body verbatim
(1588 vulnerable / 1623 fixed bytes) under a `#line` directive. Only constants,
includes and `main()` are harness-authored. Four GCC builds
(vulnerable/fixed × ASan/plain, `-O0 -g`, stack protector off) and the
unmodified `run-all.sh` gave `RUN_ALL_OK 15 PASS / 0 FAIL`; summary SHA-256
`bc87203cef79aa2033bbcec6cf48613df784a6050594010fef6606e1f781f9a4`.

- Vulnerable ASan, 293 filename bytes: `stack-buffer-overflow`, `WRITE of size
  316` at pinned `sftpserver.c:1852`; the terminating NUL is the first byte
  past `long_name[350]` for this metadata.
- Vulnerable ASan, 292 bytes: clean, `longlen=349`. Vulnerable ASan, 255 bytes:
  clean, matching this host's observed `NAME_MAX=255`.
- Vulnerable ASan, 4096 bytes: `WRITE of size 350` at `:1852`, 0 bytes past
  the 350-byte `long_name`. Plain output reports `longlen=384`: 34 chosen bytes
  plus a NUL past the array.
- Read-only GDB after the sink prints 16 chosen bytes at
  `long_name+350..+365`: sixteen `0x41` bytes with fill `0x41`, then sixteen
  `0x42` bytes with fill `0x42`.
- Fixed ASan/plain at 255 and 4096 bytes: clean; fixed 4096-byte output is
  bounded to `longlen=349`. Vulnerable plain at 255 bytes is clean.
- Negative preserved: vulnerable plain at 4096 bytes **survives** in the direct
  driver's layout. The overwrite does not reach saved control data there; no
  plain crash, saved RIP or pointer control is claimed.

The 4096-byte input deliberately exercises the sink beyond this lab
filesystem's `NAME_MAX=255`; it is not claimed to be a creatable filename on
this host. A natural server reproduction needs a filesystem permitting names
longer than the measured 292-byte boundary for the chosen metadata.

## Rung-4 feasibility and cheapest next rung

The direct sink gives deterministic ASan corruption and chosen bytes at chosen
offsets, enough for R4 LIMITED. It does not establish control flow in the real
`process_readdir()` frame. The next useful experiment is a pinned vulnerable
and fixed libssh build with its SFTP server example, driven by a local SFTP
client on `127.0.0.1`, plus a lab-controlled filesystem that actually permits
a >292-byte filename. Record the real caller's stack layout and fixed/safe
controls. If no such filesystem is available, keep the natural consumer path
UNKNOWN; a synthetic `readdir()` stub would remain harness evidence.

No rung 5 without an observed command side effect in a live target process.
The advisory's local-filesystem prerequisite and required user listing action
must remain attached to every impact claim.

## Ranking context

Kept over Pigeonhole CVE-2026-40013: libssh supplies a filename-chosen suffix
and a measured 34-byte stack overwrite, while Pigeonhole is described as a
one-byte buffer underwrite from an extreme numeric literal. libssh is not a
wire-injected filename bug and is distinct from the admitted `libsshch2shell`
channel-overflow lane.
