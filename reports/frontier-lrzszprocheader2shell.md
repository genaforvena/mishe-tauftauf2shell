# frontier brief: lrzszprocheader2shell — lrz ZMODEM filename heap overflow

Status 2026-11-27 W352: **ADMITTED 17:3xZ as the 218th declared target mind**; window 226 adopted.
Operator clean replay `4678a157` 6/6 pins and `RUN_ALL_OK 5 PASS / 0 FAIL`; independent witness replay still owed.

## Verified ground truth (claim, not assumed)

- Advisory: CVE-2026-105842 / GHSA-3cw3-cf87-8pwp, published 2026-10-06,
  "lrzsz procheader Pathname overflow". Upstream NEWS in the fixed release
  calls it a security release: "an attacker could quite easily cause an
  overflow in a malloc()ed buffer", credited to TristanInSec.
- Affected: lrzsz `< 0.13.0`; fixed `0.13.0`
  (`b18b579272fa94748388364014f22e20712288d4`). Pinned pre-fix parent
  `b1fc8a01e3a074f8462a29dca45ed7c8fd2ef665`; fix commit
  `f8caa7b1b1a3a1bb50cf08677b15be7b17c2956f` (2026-08-10). Upstream patch:
  https://github.com/UweOhse/lrzsz/commit/f8caa7b1b1a3a1bb50cf08677b15be7b17c2956f.patch
- Patch is source-readable and two lines in `src/lrz.c:1217-1220`:
  `Pathname=malloc((PATH_MAX)*2); ... strcpy(Pathname, name_static);` becomes
  `Pathname=strdup(name_static);`. The `malloc` capacity is 8192 bytes; the
  filename comes from the sender-controlled ZMODEM file header.

## Source-bound mechanism

`procheader()` (`src/lrz.c:1021`) copies the attacker-supplied file-header name
into `name_static` (`:1044-1047`), derives metadata and, for ZMODEM protocol,
allocates a fixed 8192-byte `Pathname` (`:1217`) and copies the entire chosen
name into it with `strcpy` (`:1220`). A header filename longer than 8191 bytes
writes chosen bytes past the heap allocation, at offsets chosen by the sender.
The fixed commit allocates exactly `strlen(name_static)+1`, removing the
overflow. Reproducer reaches the pinned sink through the unmodified `lrz.c`
function; the input is a file/header name, not a debugger-forced write.

## Local experiment (loopback/file only; no external target)

Harness `lab/frontier/lrzszprocheader2shell/harness/procheader-harness.c`
includes the pinned, unmodified `lrz.c` with `main` renamed and calls the real
static `procheader()` with a sender-chosen name of chosen length and byte fill;
`protocol=ZM_ZMODEM` is set to reach the sink. Both pinned trees were built with
ASan (`-fsanitize=address -fno-omit-frame-pointer -g -O1`). Lab-only build
adaptations (recorded in `PROVENANCE.md`): `AC_PREREQ` lowered 2.72→2.71 for
the host autoconf, `config.rpath` and `po/Makefile.in.in` copied from the host
gettext package, and the fixed tree built with `-Wno-error` for new warnings.
These do not touch the sink or the fix.

- Vulnerable + 16-byte name: `rc=0 Pathname_len=16`, no ASan
  (`evidence/vuln-safe.out`).
- Vulnerable + 12000-byte name, fill `0x43`: ASan `WRITE of size 12001` in
  `strcpy` at `src/lrz.c:1220`, destination 0 bytes after an 8192-byte region
  allocated at `:1217`; rc 1 (`evidence/vuln-attack.out`). Chosen byte value
  and chosen length flow to the sink.
- Fixed commit + same 12000-byte name: no ASan, `rc=-1 Pathname_len=12000`
  (`evidence/fixed-attack.out`; fixed `checkpath` rejects the long path after
  the safe `strdup`, with no out-of-bounds store). Fixed + 16-byte name: rc 0
  (`evidence/fixed-safe.out`).
Replay: `sh harness/run-all.sh` from the staging tree and from a clean
`git archive 2de80271a64426a6210da8e5fe3632072504ec86` both reported
`RUN_ALL_OK 5 PASS / 0 FAIL`. The ASan attack log's PID/ASLR addresses vary by
run; the sink, allocation and `WRITE of size 12001` are stable and are checked
by `run-all.sh`, so that volatile log is excluded from `SHA256SUMS`.

## Rung-4 feasibility and scope

R1 (deterministic chosen-name trigger), R2 (fixed-capacity allocation crossed),
R3 (ASan WRITE of chosen size at the pinned sink) and R4 at the **pinned-sink
lab scope** (chosen bytes at chosen offsets in a live copy of the receiver's
`procheader()`) are observed. R5 NOT CLAIMED: there is no shell command, no
marker execution, and the caller is a local harness rather than a live wire
session. The real ZMODEM sender path is the cheapest next experiment: replay a
ZFILE frame with an overlong filename through loopback `lrz` and confirm the
same ASan write before reducing the grade. Until that is measured, do not
describe this as a real-wire result.
