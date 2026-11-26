# sngrepsip2shell — staged status (W298, 2026-11-26)

Frontier STAGED this candidate on 2026-11-26 from verbatim upstream pins; the
operator has NOT admitted it. Admission is a standing-#6 decision owned by the
operator; an independent witness replay is owed after handoff and is not
self-acceptance.

Claim: CVE-2026-121943 (CNA VulnCheck, published 2026-11-04), CWE-170,
CVSS 6.3 v4.0 / 4.8 v3.1, affected `<= 1.9.0`. Upstream issue #589 (static
finding only); fix PR 591 merged 2026-11-06 as
`d49c96c99bfff47b41c547113cb3a39dfb9b8717`, changing two stack buffers to
`MAX_SIP_PAYLOAD + 1` and two `memset` calls to `sizeof(payload)`.

Artifacts: brief `reports/frontier-sngrepsip2shell.md`, charter
`charters/sngrepsip2shell.md`, seed wall
`.mishe-tauftauf/walls/sngrepsip2shell.md`, harness and pins
`lab/frontier/sngrepsip2shell/` (`PROVENANCE.md`, four pinned SHA-256 entries,
verbatim `sip.c` slices at raw 316-341 with `#line` mapping, GCC/clang ASan
driver, local payload vectors and traces). A live two-pane window named
`sngrepsip2shell` is registered in
`.mishe-tauftauf/operator/window-registry.json` before this status is handed
off; no duplicate window is needed.

Grade at handoff: **rung 3 ASan-confirmed stack-buffer-overflow READ of size
10241 at verbatim pinned `src/sip.c:338` from the unterminated 10240-byte
`payload` array at `:320`, GCC `-O1` and clang `-O1`.** Fixed pin on 10240,
safe 10239 and guard-rejected 10241 are clean. **Rung 1 and rung 2 NOT
CLAIMED** (plain build exits 0), **rung 4 NOT CLAIMED** (no chosen-byte
readback, adjacent live object, pointer or control-flow effect), **rung 5 NOT
CLAIMED** (direct sink call, no pcap, socket, SIP wire path or command).
`run-all.sh` PASS=13 FAIL=0 at 23:15Z.

Control gaps: only `sip_validate_packet` is harnessed; the advisory's
`sip_check_packet` and INVITE `strdup()` sinks, the live-capture/offline-pcap
path and the full `sngrep` binary are untested. The fixed pin is a merge
commit, not a numbered release. The CNA HackMD exploit link returned 403 and a
guessed VulnCheck advisory URL 404 (both negatives preserved). The reporter's
original finding was static-only; the local ASan confirmation is this plant's
own extracted-harness observation.

Owed: independent clean-archive witness replay, then an operator admission
decision. Registered grade R1 — / R2 — / R3 ✓ / R4 — / R5 —; R4/R5 NOT
CLAIMED.
