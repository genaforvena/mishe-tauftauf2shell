# opensips2shell — status

Admitted 2026-11-21 ~06:2xZ by the operator under standing approval #6 on
frontier's handoff #606 (commits `b4bc31a`, `92a9c15`, `41818af`; brief
`reports/frontier-opensips2shell.md`). Claim source: maintainer advisory
GHSA-5gm5-wj62-p234 (2026-09-28, High 8.6
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H`); no CVE ID visible at fetch
time (UNKNOWN, not asserted). Affected `>=4.0.0,<4.0.2` and
`>=3.6.0,<3.6.9`, patched `4.0.2` and `3.6.9`; upstream fix
`ec24165bc25fa462e08cdb33ee8071f58e166d36`. Claim: unbounded `sprintf` of an
XMPP JID `from` into `buf_from[256]` in `ENC_SIP_URI()` at pinned tag `4.0.1`
`xmpp.h:73-82` / `xmpp.c:280-285`, via an unauthenticated `<message/>` at
`xmpp_server.c:361-382`. Reachability gate: server mode needs
`modparam("xmpp","backend","server")`; the default component backend is not a
raw listener. The advisory claims a reliable receiver crash and RCE only as
possible depending on canary/ASLR/NX. Brief:
[frontier-opensips2shell.md](frontier-opensips2shell.md). Pins and raw URLs:
`lab/frontier/opensips2shell/PROVENANCE.md`.

- Harness: `bash lab/frontier/opensips2shell/run.sh <outdir>` — 26 PASS /
  0 FAIL, `ALL CHECKS PASSED rc 0`, canonical trace SHA-256
  `a69657bb243b83b850b332a4307996f5705d6b0bd6b3cdefbccba022c0c78b06`.
- Operator replay ~06:19Z from a clean `git archive HEAD` extraction of
  `7674a58` into two separate absolute output directories: 26 PASS / 0 FAIL
  and `ALL CHECKS PASSED rc 0` in both, trace
  `sha256=a69657bb243b83b850b332a4307996f5705d6b0bd6b3cdefbccba022c0c78b06`
  — byte-identical between directories and to the brief.
- Rungs 1/2/3 on verbatim pinned upstream lines from tags `4.0.1` and
  `4.0.2`: a 299-byte `from` writes 304 bytes (48 past `buf_from[256]`);
  with `/` at offset 10 the stored length is 14 while the write is still
  303 bytes past the prefix; ASan reports `stack-buffer-overflow`,
  `WRITE of size 304`, frame `xmpp.c:285`. Fixed helper `snprintf`s into a
  1025-byte buffer, guards the length and rejects a 1500-byte JID.
- Rung 4 INSTRUMENTED only (harness-era claim, superseded below for the live
  receiver: 16 bytes at `buf_from + 256` are byte-identical
  to the attacker pattern from `from[252]` (`CHOSEN_MATCH=1`) in the
  no-canary test frame. No return address, pointer or marker was touched;
  no daemon, socket, XMPP stream, XML parser, shipping stack layout,
  canary, ASLR or NX was exercised.
- LIVE 2026-11-27 (stock OpenSIPS 4.0.1 receiver, `backend=server`, listener
  127.0.0.1:5269): ASan reports `stack-buffer-overflow`, `WRITE of size 304`,
  frames `sprintf` → `xmpp_send_sip_msg` → `in_stream_node_callback` → expat
  → `xmpp_server_child_process`; the receiver child exits and the parent
  shuts down. Stock 4.0.1 no-canary with the same 299-byte JID overflows but
  does not crash; with a 900-byte JID the receiver SIGSEGVs after `fm_malloc`
  requests 1,111,579,232 bytes. An instrumented live-frame copy observes the
  chosen JID bytes in `fromstr.s` (`QRSTUVWX`) and `fromstr.len` (`YZAB` =
  1,111,579,225); the same fields are intact at 299 bytes. Stock 4.0.2 ASan
  ignores the stanza before dialback for both lengths. Full evidence, hashes,
  config, wire bytes and limits: `reports/opensips2shell-live-wire.md`.
- Rung 3 CONFIRMED in a live stock build. Rung 4 DEMONSTRATED security impact
  under the lab conditions (chosen bytes overwrite the live `fromstr.len` and
  force a huge allocation and crash). A stock-frame return-address overwrite
  was later observed via an early `return -1` in `uri_xmpp2sip(to, ...)`:
  eight chosen JID bytes at offsets 884-891 became `[rbp+8]`, and the `ret`
  at `xmpp_send_sip_msg+631` faulted on the non-canonical target. That is
  rung-4 control-flow diversion in a stock build, still NOT rung 5: no chosen
  code executed. A two-byte partial overwrite reached a canonical but unmapped
  target (`0x7ffff7002f6a`) because the sprintf NUL zeroed byte 2.
  A one-byte overwrite (885-byte JID, `from[884]='A'`) then kept byte 2 and
  produced a **mapped, executable** saved RIP `0x7ffff7ee0041`
  (`xmpp.so` offset `0x6041`, `sha_hash+411`); the `ret` transferred control
  there (gdb `#0` at target) but the saved RBP was non-canonical
  `0x5a59585756555453`, the next instruction is rbp-relative, and the whole
  reachable 256-byte window has no `ret` or `call`. Raw high bytes are
  rejected by expat. This is still rung 4 — mapped transfer, no chosen code.
  Rung 5 remains UNKNOWN: no valid executed target, no marker/pointer
  execution, no side effect from chosen bytes, no ASLR/NX measurement.
  Independent witness replay
  W328 (2026-11-27 08:45–08:50Z, inbox #6255) ESTABLISHED the rung-4 label as
  written: from a clean `git archive` it reproduced the harness control and all
  four live cases, and changing only `from[804:808]` from `YZAB` to `CDEF`
  moved the stock `fm_malloc` need from 1111579232 to 1178944584. NO rung 5.
  Detail: `.mishe-tauftauf/artifacts/witness-w328-opensips/detail.md`;
  evidence table: `reports/opensips2shell-live-wire.md` (one-byte section).
  Witness W331 (2026-11-27 09:55–09:58Z, inbox #6278) independently replayed
  the two-marker early-return case and the 886-byte partial from a clean
  `git archive c2fb10c5`: ESTABLISHED AS LABELED, no grade change, NO rung 5;
  exact source line corrected to `xmpp.c:294`. Detail:
  `.mishe-tauftauf/artifacts/witness-w331-opensips/detail.md`. The new
  one-byte case has NOT been replayed yet.

Next bounded work: rung 4 is settled. The `tm` gate is bypassed by the early
`return -1` in `uri_xmpp2sip(to, ...)` with a >251-byte `to`; eight chosen JID
bytes at offsets 884-891 become the saved RIP in a stock build. A full JID
gives a non-canonical target, a two-byte partial overwrite gives a canonical
but unmapped target, and the one-byte overwrite gives a mapped mid-function
target with a corrupted RBP and no `ret`/`call` in its 256-byte window. Rung 5
remains UNKNOWN without a new primitive. Any future claim needs an observed
side effect from executed chosen code and a fresh independent replay.
later wake:
GHSA-qc7q-vrx3-3j4h (`sip_i` `parse_isup` length-controlled `memcpy` into
`val[128]`), recorded from operator inbox #6227 and deliberately not worked.
