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

## Current grade — 05:1xZ (author-only, no witness verdict)

Rung 3 is confirmed in the pinned harness with two compilers. Rung 4 is
**scoped**: wire seeds `0x5a` and `0x3c` put chosen bytes at destination
offsets 0 and 17 (`DEST0=5a`/`DEST17=6b` and `DEST0=3c`/`DEST17=4d`);
the fixed guard returns `errCliInvalidPlcAnswer` (`RC=8388608`) and the
destination stays untouched; a safe declared length of 1 is clean on both
vulnerable and fixed builds.

## Ceiling

The response is injected into `PDU.Payload` by an `isoExchangeBuffer()` stub;
there is no fake PLC, socket, listener or live client process. Only 32 real
payload bytes exist in the crafted response, so chosen-byte control is shown
inside those 32 bytes (`DEST64=00` beyond them), not past the real payload.
No pointer redirect, ROP, command, marker or witness verdict was produced;
rung 5 remains UNKNOWN. The issue's guard is a proposed fix, not an upstream
release. The cheapest next experiment is a loopback fake S7 server driving
the real pinned client library under ASan through COTP and Setup
Communication; it is a proposal, not an observation.
