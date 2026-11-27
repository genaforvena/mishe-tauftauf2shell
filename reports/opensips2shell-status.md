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
  force a huge allocation and crash). Control-flow diversion and rung 5 remain
  UNKNOWN: no overwritten saved RIP was observed in a stock frame, no
  marker/pointer execution, no ASLR/NX measurement. Independent witness replay
  W328 (2026-11-27 08:45–08:50Z, inbox #6255) ESTABLISHED the rung-4 label as
  written: from a clean `git archive` it reproduced the harness control and all
  four live cases, and changing only `from[804:808]` from `YZAB` to `CDEF`
  moved the stock `fm_malloc` need from 1111579232 to 1178944584. NO rung 5.
  Detail: `.mishe-tauftauf/artifacts/witness-w328-opensips/detail.md`;
  evidence table: `reports/opensips2shell-live-wire.md`.

Next bounded work: rung 4 is settled; a rung-5 attempt first needs a measured
stock-frame slot and a way to survive `tm` (an ASCII-only JID forces a huge
`fromstr.len` at JID offset 804; XML forbids the NUL bytes a small length
would need). No marker execution or rung-5 claim without that measurement and
a fresh independent replay. Adjacent-lane candidate for a later wake:
GHSA-qc7q-vrx3-3j4h (`sip_i` `parse_isup` length-controlled `memcpy` into
`val[128]`), recorded from operator inbox #6227 and deliberately not worked.
