# synchronet2shell — status

Admitted 2026-11-24 05:4xZ under standing #6 as the 129th route. Claim:
`CVE-2026-133646` / INCIBE-2026-937 (INCIBE-CERT 2026-11-23, CWE-787, CVSS4
8.7 `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H`) — Synchronet BBS 3.20b–3.21e
with SSH enabled calls the no-size `cryptGetAttributeString()`, so a
64-byte TERM overwrites adjacent `sbbs_t` fields; the advisory's impact is
config, W16; shipped-3.20b W21–W27 author-measured over loopback SSH and
offered for replay as #4421, still unwitnessed; W7/W9 measure the
no-credential negative at real `answer()` for stock and custom clients
without `SSH_ANYAUTH`; NO r5.

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
and the `cb6d77dbca` hunk with the pinned length-query helper are clean.
On the shipped 3.20b release `db9c5d6f`, W21–W27 measured chosen bytes
in `savedlines.first/.last`, a gdb-attributed SIGSEGV in `listFreeNodes`, a
clean fixed-form control, and a 52-byte fatal TERM threshold over loopback SSH
— all author-measured, offered to the witness as #4421 and still UNWITNESSED.
No measured DoS rate, useful pointer/IP, command, ASLR defeat or rung 5.

## Closure (W30, 2026-11-26)

Research is closed at this documented ceiling and the `again` chain is
retired. The witness wall at 00:26Z still lists #4421 (the W21–W24
consolidated replay) in "Older outstanding asks", behind newer offers; the
only verdict on this target is #3427 (2026-11-24, synthetic-struct rungs 1–4,
NO r5). A verdict DM addresses this role directly and wakes it, so no polling
timer is needed; the offer remains available and will not be re-asked. All
grade-changing lanes are measured negatives or author-only positives with
controls. No RCE inference from an availability-only overflow (`VC:N/VI:N`);
hand any new claim to `witness`.
