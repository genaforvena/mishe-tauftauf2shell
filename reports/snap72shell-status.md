# snap72shell — status

Admitted 2026-11-23 ~05:1xZ under standing approval #6 as the 101st engine
route. Frontier staged this lane after W136 screened Snap7 out for lack of
patch bytes; reporter issue #32 now supplies a source-bound suggested fix,
recorded with the pinned vulnerable bytes, harness and raw evidence in
`lab/frontier/snap72shell/PROVENANCE.md` and the brief at
`reports/frontier-snap72shell.md`. The two-pane inner tmux window already
existed at index 105 (frontier verified both panes render) with a registered
two-pane entry, so admission created no second window and changed no registry
entry. The hy4-flash `max_parallel: 3` route was added; the path, debounce and
`@snap72shell` slice drop-in were minted with the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), followed
by `systemctl --user daemon-reload`; the path unit is enabled and active. Both
`m2shell-wake@snap72shell.service` and `m2shell-wake-snap72shell.path` were
added to the site's owner resolver map. The pinned full-flag doctor returned
rc 0, `PASS local plant out of Git` / `GREEN`. Admission changes no grade.

- Claim: CVE-2026-131848 / GHSA-xr6p-cjp3-pvwg (NVD CNA, published
  2026-11-18; VulnCheck advisory dated 2026-11-17), HIGH 8.3
  `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N`, CWE-787.
  Affected Snap7 through 1.4.3; upstream HEAD
  `30f37da3114024a71ba93f7fd855c680b97a406f` is still vulnerable and no
  upstream fixed version or fix commit exists. The fixed control is the
  issue-#32 derived guard (`a4127166…`), deliberately weaker than an upstream
  fixed blob. `AT:P` requires a malicious or impersonating PLC.
- Primitive: pinned `s7_micro_client.cpp::opReadMultiVars()` checks only the
  returned item **count** at line 400, takes the per-item copy length
  `Slice = SwapWord(ResData[c]->DataLength)` from the response at line 413,
  does not divide it on the `TS_ResOctet = 0x09` path, and `memcpy`s that many
  bytes into caller-owned `Item->pdata` at line 418. `DataLength = 0xffff`
  gives a 65535-byte write into a one-byte destination. Line 427 advances by
  the same unvalidated length.
- Evidence: `lab/frontier/snap72shell/harness/run.sh` re-extracts pinned lines
  307–431 verbatim every run, asserts all source/harness SHA-256 pins and
  builds plain and ASan variants with gcc and clang. Frontier recorded 43
  PASS / 0 FAIL three times plus a clean `/tmp` replay, normalized trace
  `24c8438c85474ab76ade31d8c9d98e1a510f926b4f97cf6ee8948208427eda59`.
  Operator replay from `git archive HEAD lab/frontier/snap72shell` in a fresh
  `/tmp` directory returned rc 0, `PASS=43 FAIL=0` and exactly that trace
  hash. Rung 1 logs `DATALEN=65535`, `SLICE=65535`, `MAXDEST=1`.
  gcc and clang ASan report `heap-buffer-overflow`, `WRITE of size 65535`,
  0 bytes after a 1-byte region, in `opReadMultiVars()` at pinned line 418.

## Current grade — 2026-11-23 (independent witness ESTABLISHED, lab-wire scope)

Rung 3 is confirmed in the pinned harness with two compilers. Rung 4 is
**wire-reachable in the lab** (W1): a plant-written fake S7 responder bound to
127.0.0.1 drives the real pinned client library under ASan through COTP CR/CC
and Setup Communication, then answers `Cli_ReadMultiVars()` with
`ReturnCode=0xFF`, `TransportSize=0x09`, `DataLength=0xFFFF`. The live client
reports `heap-buffer-overflow`, `WRITE of size 65535`, 0 bytes after the
one-byte caller allocation, in `opReadMultiVars()` at pinned line 418. Two
consecutive `run_live.sh` replays matched normalized trace SHA-256
`1f25bf6311e1a659e4da947abc07d001cfacc5fe39dd67618560e425df3773d4`
(`live/evidence/normalized.txt`, `replay1.txt`, `replay2.txt`). An independent
witness rebuilt from a clean `git archive` of HEAD under its own source root,
got rc 0 on all five cases, and changed its responder bytes to `a7`/`3c`: the
live plain client read `DST0=a7 DEST17=3c`, confirming the chosen bytes come
from the wire, not a server-side echo. W2 measured the chosen-byte extent: all
4000 real response bytes land byte-exact (`MATCHES=4000`,
`FIRST_BAD_OFFSET=4000`), normalized hash
`f254a539df2d8dd63c5dbb54e9dc6d1c8f9a7536c746768e159f817ee87c3808`.
Both controls hold on the live wire: the guard returns
`errCliInvalidPlcAnswer` (`RC=8388608`) and is ASan-clean; a safe one-byte
response returns 0 with `DST0=5a`. The witness verdict ESTABLISHED applies to
this explicitly labeled lab-wire scope only.

W5 also measured a two-item response on the live wire (`run_multi.sh`,
normalized hash
`e4983fed2bd7ebc3bf8fc81caf35eba7b996bc2889f893313efe0439eed7d63c`). Item 0
declaring `0xFFFF` advances the pinned line-427 offset by 65540, so item 1's
header is read outside the response: both builds report
`ITEM0_RESULT=0 ITEM1_RESULT=36700160 DST1_0=cc` with no ASan report and no
second `memcpy`. The two-item safe control returns both results 0 and
`DST1_0=77`. The read lands in the client object's own 65536-byte `opData`, so
the item-1 result is stale client state, not peer-controlled. The 4000-byte
chosen-byte extent is compile-time bounded (`s7_isotcp.h:38`,
`s7_partner.cpp:660-661`); no public API raises it. Grade unchanged.

The witness then independently verified W5 (message #2383, tape): a clean
`git archive` at HEAD `1f8f9b9` into `/tmp/w149-snap7`, pins regenerated from
the hash-matched local tarball `2840d50a…c613c36`, `run_multi.sh` twice rc0
with 4/4 cases and the exact normalized hash above. Both builds reported
`ITEM0_RESULT=0 ITEM1_RESULT=36700160 DST1_0=cc` with no ASan report; the safe
control returned 0/0 and `DST1_0=77`. Raw `run_live.sh` and `run_wide.sh`
hashes matched the tracked author evidence byte-for-byte; the earlier
`1f25bf63…` normalized-hash difference is only the absolute ASan source path
in the normalizer (known NIT, deliberately unchanged). ESTABLISHED at the
labeled lab-wire scope, no new rung; the witness wrote no repository files
and left no processes.

## Ceiling

The attacker must control or impersonate a PLC (`AT:P`); the 127.0.0.1
responder is plant-written and no real PLC or external host is involved.
Peer-chosen control is bounded by the 4096-byte Iso payload and `CheckPDU()`'s
TPKT cap (`s7_isotcp.h:38`, `s7_isotcp.cpp:46-65`) to 4000 measured bytes, not
the 65535-byte copy length; bytes past the real payload are zeroed PDU buffer
(plain) or stale stack (ASan), not peer-controlled. After the copy,
`PerformOperation()` (pinned lines 2632-2634) touches only the stack-resident
`Job`. A plain-build probe (`lab/frontier/snap72shell/live/run_freeprobe.sh`)
measured the caller fate directly: destination sizes 1, 1032, 2048, 4096, 8192
and 16384 all die with SIGSEGV inside the pinned line-418 `memcpy` at the brk
page boundary, before `delete[] dst` is reached; the 200000-byte mmap-backed
control exits 0 without overflowing. No post-overflow dereference of adjacent
heap state is reachable in this client on this host.
No pointer redirect, ROP, command, marker or rung 5 observation exists; rung 5
remains UNKNOWN. No upstream fixed version or fix commit exists; the guard is
issue #32's proposed fix, deliberately weaker than an upstream fixed blob.

Exact replays: `bash lab/frontier/snap72shell/live/run_live.sh`,
`bash lab/frontier/snap72shell/live/run_wide.sh`,
`bash lab/frontier/snap72shell/live/run_multi.sh` and
`bash lab/frontier/snap72shell/live/run_freeprobe.sh`. Full hashes, frames and
raw logs are in `lab/frontier/snap72shell/PROVENANCE.md` and `live/evidence/`.
