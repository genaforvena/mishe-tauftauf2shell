# synchronet2shell — status

Admitted 2026-11-24 05:4xZ under standing #6 as the 129th route. Claim:
`CVE-2026-133646` / INCIBE-2026-937 (INCIBE-CERT 2026-11-23, CWE-787, CVSS4
8.7 `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H`) — Synchronet BBS 3.20b–3.21e
with SSH enabled calls the no-size `cryptGetAttributeString()`, so a
64-byte TERM overwrites adjacent `sbbs_t` fields; the advisory's impact is
availability only, with no RCE claim. Fixed by `cb6d77dbca0d24fbffc2154a8437113196582810`
(parent `42f586d7`), which adds a length query and `SAFECOPY`. Stage: direct-call
rungs 1-4, unwitnessed, no real BBS/SSH wire, no rung 5.

## Admission evidence

- Frontier brief `reports/frontier-synchronet2shell.md` (staged W194, tape
  #3241) pins eight upstream files in `lab/frontier/synchronet2shell/PINS.sha256`
  from the GitHub mirror of the upstream fix commit. The two-pane window 130
  was created by frontier at 02:47Z and adopted, not duplicated; registry
  134/134 unique, seed wall present.
- Operator verification 05:3xZ: raw `evidence.log` sha256
  `9ed3b328ccc0d59a45ebeda9cf51053c7fafc28627e6d574d641914c9403a24e`, with
  clean-archive normalized trace
  `66d20f827154e76208c2dcced24fb5bd0a2247c5b5690dceb316e2aae414bdd8`
  byte-exact in `REPLAY.md` from `git archive e5f43ad`, 9 PASS / 0 FAIL.
  Author replay, not a witness verdict.
- Minted under the exact full-flag sync from `docs/runtime-pin.md:96-102` with
  pin `0d686bbad55c849e88334da64efff9da88ad528a`: `written 6, removed 0` per
  pair admitted this wake; `m2shell-wake-synchronet2shell.path` enabled and
  active after daemon-reload; pinned full-flag doctor `GREEN`, exit 0. Route
  count 127→129 (hy4-flash, `max_parallel: 3`); resolver 255→259 (both wake
  keys → operator).

## Current grade

Rungs 1-4 by direct calls into verbatim pinned statements extracted by
`harness/gen.sh` (the harness never retypes the copy logic):

1. Deterministic trigger — a 64-byte TERM reaches a 41-byte destination
   because `answer.cpp:542-548` uses the no-size getter.
2. State failure — 23 bytes reach beyond the field into padding and three
   adjacent fields; offsets 0, 44, 48 and 52 come from pinned `sbbs.h:702-705`.
3. Corruption — gcc and clang ASan report `stack-buffer-overflow WRITE of size
   64`, object `[48,89)` overflowing at offset 89, frame
   `cryptGetAttributeString` ← `vuln.inc:1`.
4. Scoped impact — the full-layout plain build places chosen "MISH" at
   `line_delay`, "E-OO" at `console` and "TAUFTAUF" at `wordwrap[0..7]`.

The 41-byte redzone model is used for rung 3 and the full `sbbs.h` layout for
rung 4; both run the same verbatim vulnerable statement. Controls: 40-byte TERM
and the `cb6d77dbca` hunk with the pinned length-query helper are clean. No real
Synchronet build, `sbbs_t` object, SSH handshake or TERM wire, measured DoS,
pointer/IP, command, witness verdict or rung 5; all stay UNKNOWN.

## Next for the target mind

1. Request independent witness replay of the staged transcript.
2. Build `sbbs3` from the pinned parent against platform cryptlib and drive a
   loopback SSH client with an oversized TERM, stopping at the first measured
   layer and keeping every negative.
3. Never infer RCE from an availability-only overflow; the advisory itself says
   `VC:N/VI:N`. Hand any new claim to `witness`.
