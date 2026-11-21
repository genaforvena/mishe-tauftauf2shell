# PROVENANCE — asterisk2shell harness

All source bytes below were fetched read-only from public upstream mirrors as
provisioning. No external system was probed; the harness builds nothing that
binds a socket and contacts no host, loopback or otherwise.

## Advisory ground truth

- Maintainer advisory: https://github.com/asterisk/asterisk/security/advisories/GHSA-x348-j6c9-77f3
  (published 2026-06-25, `gtjoseph`; title "Stack Buffer Overflow in H.323
  ooTrace() via Unbounded vsprintf into Fixed 2048-byte Buffer"; High 8.1,
  `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`, CWE-787; credit
  @HarutoKimura).
- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-57201 and
  https://cveawg.mitre.org/api/cve/CVE-2026-57201 (CNA GitHub, Inc.,
  published/updated 2026-10-27; 7.5 HIGH,
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, CWE-787). **The two sources
  disagree on AC and on C/I impact.** This brief ranks conservatively on the
  CVE's availability-only vector; no C/I impact was observed locally.
- Fix commits listed in the CVE references (backports across maintained
  branches): `2d7b8c8dc13d9ead8b6f36cc38b6dd91cd4abd3a`,
  `33f62e351642edd9c58ef97b0002132722546af9`,
  `875ac7413de0b7068cd12d0da2f140cd06ba9357`,
  `ac0a64dec6d4231bf005a68da6af3e02bb311634`,
  `bf0c9a906892bc0f91fa753476e326919e4e30e5`,
  `c4d9b4defe83f74523880fd630c02c49683786a3`,
  `fff256d0539e96f70ac315844d72e9d540f03a4c`.
- Fix patch read verbatim:
  https://github.com/asterisk/asterisk/commit/2d7b8c8dc13d9ead8b6f36cc38b6dd91cd4abd3a.patch
  ("ooh323: Prevent potential buffer overflow in trace logging", Mike Bradeen,
  author date 2026-03-31, committer date 2026-06-25). It changes only
  `addons/ooh323c/src/ootrace.c`, replacing `char logMessage[MAXLOGMSGLEN];` +
  `vsprintf(logMessage, fmtspec, arglist);` with `char *logMessage = NULL;` +
  `ast_vasprintf(&logMessage, fmtspec, arglist);`.

## Exact pinned bytes

Fetched from `raw.githubusercontent.com/asterisk/asterisk/<ref>/addons/ooh323c/src/`:

| file | ref | role | sha256 |
| --- | --- | --- | --- |
| `pins/ootrace.affected.c` | `661d6a2fc5cc7744ab9d849ed3c73ae5066386df` (fix parent) | affected | `5d2cd33e1d51251759a70b8b8f65dd89a1a207eb889f50f9979923699fa46e5b` |
| `pins/ootrace.fixed.c` | `2d7b8c8dc13d9ead8b6f36cc38b6dd91cd4abd3a` (fix) | fixed | `a5158c90bfa2f07eeb53d4fced5b1eb5ef789fb60841c8798e4357ec0a9b8122` |
| `pins/ootrace.h` | `661d6a2fc5cc7744ab9d849ed3c73ae5066386df` | `TRACELVL` provenance | `3e0d049d544302c597c3fecea29783d642aa10c1ea536e2a2862f1d5fbf9dcee` |

Additional fetch, release tag `23.4.0`
(`pins/ootrace.rel2340.c`, not used by the harness): sha256
`5d2cd33e1d51251759a70b8b8f65dd89a1a207eb889f50f9979923699fa46e5b` —
**byte-identical to the fix parent**, so the A/B pair differs only by the fix
commit itself. Release `23.4.1` is the patched counterpart.

`pins/ootypes.h` (same affected ref) defines `#define MAXLOGMSGLEN 2048` at
line 149: https://raw.githubusercontent.com/asterisk/asterisk/661d6a2fc5cc7744ab9d849ed3c73ae5066386df/addons/ooh323c/src/ootypes.h
`pins/ootrace.h` lines 51–52 define `TRACELVL 1` when no `OOTRCLVL*` macro is
selected.

## Harness construction

`run.sh` verifies the pinned sha256 values, asserts the exact upstream lines
and their line numbers, then extracts lines **35–53** of the affected pin and
**35–57** of the fixed pin verbatim into `gen_block.h` under
`#line 35 "ootrace.c"`. `driver.c` includes that header at file scope; no
production statement is reimplemented.

Harness-only scaffolding, all labelled in `driver.c`:

- `typedef unsigned int OOUINT32;` and the two `#define`s copied from the
  pinned headers (values and provenance above).
- `ooTraceLogMessage()` stub: the real upstream function writes to
  `gH323ep.fptraceFile`; the stub records the buffer pointer and length only.
- `ast_vasprintf()`/`ast_free()` stubs (fixed build only): reproduce the Asterisk
  core contract of exact-size heap allocation, return length, and release.
- A 512-byte stack `victim` in the caller frame, a measured stack delta, a
  `setjmp`/`longjmp` escape that observes the victim before the overflowed
  saved return address is used (plain build), and a token-safe `AST2SHELL`
  marker. No live daemon, socket, useful pointer control or execution.

## Replay

`bash lab/frontier/asterisk2shell/run.sh <outdir>` — 24 PASS, `ALL CHECKS PASS
rc 0`. Canonical trace SHA-256
`51b5ff1b82684092340d5bd93105efed76e453681e552eb0bb84103eb74feee0`,
byte-identical across repeated runs. Canonical lines only; raw ASan PID,
address and path text is filtered out of the trace.
