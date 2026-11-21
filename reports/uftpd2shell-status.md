# Uftpd2Shell status

Admitted 2026-11-21 ~02:4xZ under the standing similar-things mandate (#6),
on frontier's #496 handoff. Claim sources, pinned sources, hashes and URLs:
`reports/frontier-uftpd2shell.md` and
`lab/frontier/uftpd2shell/PROVENANCE.md`. The two-pane `uftpd2shell` window
(inner socket, window 26), registry entry and seed wall were already live
from frontier (capture-verified 02:32Z); wake trigger units and the
presentation.json entry are owed from the person's full-flag sync
(`docs/runtime-pin.md`) — never a bare `mishe sync`.

## Target

uftpd `compose_path()` overlong-path stack overflow, CVE-2026-59964 /
GHSA-vqhc-mmjf-972h (CWE-121, CVSS 3.1 5.9 MEDIUM
`AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H`, CNA GitHub_M, published
2026-11-18). Affected `< 2.16`; fixed `2.16`; fix commit
`f5552a8c6a5f14691f51bef1f3373747259d7ac8` adds an 11-line guard before
the `memmove`. With the server running **without chroot**, a logged-in FTP
client (anonymous/guest where enabled) sends a near-`PATH_MAX` path;
`compose_path()` shifts the capped `dir[PATH_MAX]` right by the configured
home length, writing that many bytes past the stack buffer. CWD, RETR,
STOR and LIST reach it. The advisory claims memory corruption and a
reliable crash; RCE is not demonstrated and is not claimed here. The
`PR:L` and no-chroot gates are part of every impact claim.

## Reproduction and pins

`bash lab/frontier/uftpd2shell/run.sh <outdir>` extracts the **verbatim**
pinned upstream `compose_path()` at v2.15/v2.16 at replay time (minimal
stand-in header only; gcc 13.3.0, `-O0 -g`). Operator replay at admission:
23 PASS lines, `ALL CHECKS PASS rc 0`, deterministic trace
`sha256=ad11094aa03e898df6c3b00a83b6b8ba8a9b049e0a0a18bf5fd952475d09d33b`,
matching the brief and its three byte-identical frontier replays.

- Rung 1 — `path_len=4095` (`PATH_MAX-1`), configured `home_len=128`,
  `expected_oob=128`; the vulnerable upstream `memmove` is reached.
- Rung 2 — the plain `-fstack-protector-all` build aborts with
  `*** stack smashing detected ***`; the OOB write hit the frame canary.
- Rung 3 — ASan `stack-buffer-overflow`, `WRITE of size 4096`, victim
  `dir` `[256, 4352)`, first bad address at offset `4352`
  (`overflows this variable`); frame `compose_path` at pinned
  `common.c.v2.15:61`, buffer declared at `:36`.
- Rung 4 — chosen `UFTPD2SHELL!` marker (first four bytes `55465450`) and
  `0x1122334455667788` at `+40` are supplied in the client path and
  written by the upstream `memmove`. INSTRUMENTED only.
- Fixed control — pinned v2.16 NUL-terminates `dir` before the `memmove`;
  same input gives rc 0, no canary abort, `returned=null`.

## Evidence boundary

Rungs 1/2/3 ESTABLISHED on the verbatim pinned upstream function. Rung 4 is
INSTRUMENTED chosen-byte control in that function's frame, not pointer
control in a stock binary. No live uftpd process, stock frame layout,
useful-pointer control or execution was observed. Whether the default
`/srv/ftp` home's 9-byte overflow reaches a control datum is UNKNOWN.
Witness replay is owed; the author's brief is not independent acceptance.

## Probe policy

All replay work is local and file-only. Any future live server binds to
127.0.0.1 only; no public infrastructure is contacted.
